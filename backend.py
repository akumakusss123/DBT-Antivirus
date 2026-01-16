# backend.py - ВЕСЬ БЭКЕНД В ОДНОМ ФАЙЛЕ С POSTGRESQL
import os
import hashlib
import tempfile
import uuid
import random
import json
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

# ================== КОНФИГУРАЦИЯ ==================
app = Flask(__name__)
CORS(app)  # Разрешаем запросы с фронтенда

# Твой ключ VirusTotal
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'КЛЮЧ')
MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 МБ

# ================== POSTGRESQL ПОДКЛЮЧЕНИЕ ==================
import psycopg2
from psycopg2.extras import RealDictCursor

class Database:
    def __init__(self):
        self.conn = None
        self.connect()
    
    def connect(self):
        """Подключение к PostgreSQL"""
        try:
            # ⚠️ 
            self.conn = psycopg2.connect(
                host="localhost",          # localhost
                database="XXX", # БД (с пробелом!)
                user="postgres",          # Стандартный пользователь
                password="XXX",      # ПАРОЛЬ ОТ POSTGRES! 12345 - shool
                port="5432"               # Стандартный порт  ++
            )
            print("✅ PostgreSQL подключена успешно!")
            self.init_tables()
        except Exception as e:
            print(f"❌ Ошибка подключения к PostgreSQL: {e}")
            print("🔧 Решения:")
            print("1. Проверь запущен ли PostgreSQL (pgAdmin)")
            print("2. Проверь пароль в строке 34 этого файла")
            print("3. Проверь название базы данных")
            print("4. Используй DEMO режим для школы")
            self.conn = None
    
    def init_tables(self):
        """Создаём таблицы если их нет"""
        if not self.conn:
            return
        
        try:
            cursor = self.conn.cursor()
            
            # Таблица сканирований
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id SERIAL PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL,
                    file_hash VARCHAR(64) NOT NULL,
                    file_size BIGINT,
                    status VARCHAR(20) NOT NULL,
                    vt_detections INTEGER DEFAULT 0,
                    vt_total INTEGER DEFAULT 70,
                    clamav_result TEXT,
                    virus_names TEXT,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Индексы для быстрого поиска
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_hash ON scans(file_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_date ON scans(scan_date DESC)')
            
            self.conn.commit()
            cursor.close()
            print("✅ Таблицы PostgreSQL созданы")
        except Exception as e:
            print(f"❌ Ошибка создания таблиц: {e}")
    
    def save_scan(self, result):
        """Сохраняем результат сканирования в PostgreSQL"""
        if not self.conn:
            print("⚠️ PostgreSQL не подключена, используем DEMO режим")
            return None
        
        try:
            cursor = self.conn.cursor()
            
            # Формируем строку с названиями вирусов
            virus_names = []
            if result['virustotal'].get('engines'):
                for virus in result['virustotal']['engines'].values():
                    virus_names.append(virus)
            if result['clamav'].get('result') and result['clamav']['result'] != 'OK':
                virus_names.append(result['clamav']['result'])
            
            # Вставляем запись
            cursor.execute('''
                INSERT INTO scans 
                (filename, file_hash, file_size, status, vt_detections, vt_total, clamav_result, virus_names)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (
                result['filename'],
                result['hash'],
                result['size'],
                result['status'],
                result['virustotal']['detections'],
                result['virustotal']['total'],
                result['clamav']['result'],
                ', '.join(virus_names) if virus_names else None
            ))
            
            scan_id = cursor.fetchone()[0]
            self.conn.commit()
            cursor.close()
            
            print(f"💾 Сохранено в PostgreSQL, ID: {scan_id}")
            return scan_id
            
        except Exception as e:
            print(f"❌ Ошибка сохранения в PostgreSQL: {e}")
            return None
    
    def get_history(self, limit=20):
        """Получаем историю сканирований"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute('''
                SELECT 
                    id, filename, file_hash, status, 
                    vt_detections, vt_total, clamav_result,
                    TO_CHAR(scan_date, 'DD.MM.YYYY HH24:MI') as scan_date,
                    virus_names
                FROM scans 
                ORDER BY scan_date DESC 
                LIMIT %s
            ''', (limit,))
            
            results = cursor.fetchall()
            cursor.close()
            return results
            
        except Exception as e:
            print(f"❌ Ошибка получения истории: {e}")
            return []
    
    def get_stats(self):
        """Получаем статистику из PostgreSQL"""
        if not self.conn:
            return {'total_scans': 0, 'threats_found': 0, 'clean_files': 0}
        
        try:
            cursor = self.conn.cursor()
            
            # Основная статистика
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_scans,
                    SUM(CASE WHEN status = 'THREAT_DETECTED' THEN 1 ELSE 0 END) as threats_found,
                    SUM(CASE WHEN status = 'CLEAN' THEN 1 ELSE 0 END) as clean_files,
                    MAX(scan_date) as last_scan
                FROM scans
            ''')
            
            row = cursor.fetchone()
            stats = {
                'total_scans': row[0] or 0,
                'threats_found': row[1] or 0,
                'clean_files': row[2] or 0,
                'last_scan': row[3]
            }
            
            cursor.close()
            return stats
            
        except Exception as e:
            print(f"❌ Ошибка получения статистики: {e}")
            return {'total_scans': 0, 'threats_found': 0, 'clean_files': 0}

# ================== СКАНЕР ==================
class AntivirusScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        print(f"🔑 VirusTotal: {'API КЛЮЧ АКТИВЕН' if api_key else 'ДЕМО-РЕЖИМ'}")
    
    def calculate_hash(self, file_path):
        """Вычисляем SHA-256 хеш"""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def check_virustotal(self, file_hash, filename):
        """Демо-режим VirusTotal для школы"""
        print(f"🌐 Проверка в VirusTotal (DEMO)...")
        
        # EICAR тестовый файл
        if file_hash == "131f95c51cc819465a5e32bc2a4afce6980975a1c2b6c06e88c6b0b6da3c6c6a":
            return {
                'detected': True,
                'detections': 10,
                'total': 70,
                'engines': {
                    'Kaspersky': 'EICAR-Test-File',
                    'Avast': 'EICAR-Test-File',
                    'Bitdefender': 'EICAR-Test-File'
                }
            }
        
        # Для .exe файлов - 40% шанс угрозы
        if filename.lower().endswith('.exe'):
            if random.random() < 0.4:
                return {
                    'detected': True,
                    'detections': random.randint(2, 8),
                    'total': 70,
                    'engines': {
                        'DemoAV': 'Trojan.Generic',
                        'AnotherAV': 'RiskWare'
                    }
                }
        
        # Для остальных - 90% чистые
        return {
            'detected': False,
            'detections': 0,
            'total': 70,
            'engines': {}
        }
    
    def check_clamav(self, file_path, filename):
        """Демо-режим ClamAV"""
        print(f"🦠 Проверка в ClamAV (DEMO)...")
        
        # Проверяем EICAR в содержимом - ИСПРАВЛЕННАЯ СТРОКА!
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' in content:
                    return {
                        'detected': True,
                        'result': 'Eicar-Test-Signature'
                    }
        except:
            pass
        
        # Подозрительные расширения
        suspicious_ext = ['.exe', '.dll', '.js', '.vbs', '.bat', '.ps1', '.scr']
        if any(filename.lower().endswith(ext) for ext in suspicious_ext):
            if random.random() < 0.3:
                return {
                    'detected': True,
                    'result': 'Trojan.Generic.123456'
                }
        
        return {
            'detected': False,
            'result': 'OK'
        }
    
    def scan_file(self, file_path, filename):
        """Основная функция сканирования"""
        print(f"\n🔍 Начинаю сканирование: {filename}")
        
        # 1. Вычисляем хеш
        file_hash = self.calculate_hash(file_path)
        print(f"📊 SHA-256: {file_hash[:16]}...")
        
        # 2. Проверяем в VirusTotal (демо)
        vt_result = self.check_virustotal(file_hash, filename)
        
        # 3. Проверяем в ClamAV (демо)
        clamav_result = self.check_clamav(file_path, filename)
        
        # 4. Определяем общий статус
        if vt_result['detected'] or clamav_result['detected']:
            status = 'THREAT_DETECTED'
            print(f"⚠️  ОБНАРУЖЕНА УГРОЗА!")
        else:
            status = 'CLEAN'
            print(f"✅ Файл чистый")
        
        # 5. Формируем результат
        result = {
            'filename': filename,
            'hash': file_hash,
            'size': os.path.getsize(file_path),
            'timestamp': datetime.now().isoformat(),
            'status': status,
            'virustotal': vt_result,
            'clamav': clamav_result,
            'postgresql': 'ready'
        }
        
        return result

# ================== ИНИЦИАЛИЗАЦИЯ ==================
scanner = AntivirusScanner(VIRUSTOTAL_API_KEY)
db = Database()  # Подключаемся к PostgreSQL

# ================== API ЭНДПОИНТЫ ==================
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>DBT Antivirus API</title>
        <style>
            body { font-family: monospace; background: #0a001a; color: #00ff88; padding: 40px; }
            h1 { color: #9d00ff; text-shadow: 0 0 10px #9d00ff; }
            .container { max-width: 800px; margin: 0 auto; }
            .endpoint { background: #11111f; padding: 15px; margin: 10px 0; border-left: 3px solid #9d00ff; }
            .postgres { color: #336791; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔥 DBT ANTIVIRUS API v2.0</h1>
            <p><span class="postgres">🗄️ PostgreSQL: dbt antivirus</span></p>
            <p>Фронтенд: <a href="http://localhost:8080" style="color: #00e1ff;">http://localhost:8080</a></p>
            
            <h2>📊 API Эндпоинты:</h2>
            <div class="endpoint">
                <strong>GET /api/status</strong> - Статус сервера
            </div>
            <div class="endpoint">
                <strong>POST /api/scan</strong> - Сканирование файла (сохраняет в PostgreSQL)
            </div>
            <div class="endpoint">
                <strong>GET /api/history</strong> - История сканирований
            </div>
            <div class="endpoint">
                <strong>GET /api/stats</strong> - Статистика
            </div>
            <div class="endpoint">
                <strong>GET /api/test/eicar</strong> - Тестовый вирус EICAR
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/api/status', methods=['GET'])
def api_status():
    # Проверяем реальное соединение с PostgreSQL
    postgres_connected = False
    if hasattr(db, 'conn') and db.conn:
        try:
            cursor = db.conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            postgres_connected = True
            cursor.close()
        except:
            postgres_connected = False
    
    return jsonify({
        'status': 'online',
        'service': 'DBT Antivirus API',
        'version': '2.0',
        'database': 'PostgreSQL',
        'connected': postgres_connected,
        'postgresql': {
            'connected': postgres_connected,
            'tables': ['scans', 'stats'] if postgres_connected else [],
            'timestamp': datetime.now().isoformat()
        },
        'scanner': 'ready'
    })

@app.route('/api/scan', methods=['POST'])
def scan_file():
    """Сканирование файла с сохранением в PostgreSQL"""
    if 'file' not in request.files:
        return jsonify({'error': 'Файл не предоставлен'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'Файл не выбран'}), 400
    
    # Проверяем размер файла
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > MAX_FILE_SIZE:
        return jsonify({'error': f'Файл слишком большой (макс {MAX_FILE_SIZE // 1024 // 1024} МБ)'}), 400
    
    # Сохраняем временный файл
    temp_dir = tempfile.gettempdir()
    temp_filename = f"scan_{uuid.uuid4().hex}_{file.filename}"
    temp_path = os.path.join(temp_dir, temp_filename)
    
    try:
        file.save(temp_path)
        
        # Сканируем файл
        result = scanner.scan_file(temp_path, file.filename)
        
        # Сохраняем в PostgreSQL
        scan_id = db.save_scan(result)
        if scan_id:
            result['postgresql_id'] = scan_id
            result['message'] = 'Сохранено в PostgreSQL'
        
        # Удаляем временный файл
        os.remove(temp_path)
        
        return jsonify(result)
        
    except Exception as e:
        # Удаляем временный файл при ошибке
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except:
            pass
        
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """История сканирований из PostgreSQL"""
    history = db.get_history()
    
    return jsonify({
        'success': True,
        'database': 'PostgreSQL' if db.conn else 'Demo Mode',
        'count': len(history),
        'scans': history
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Статистика из PostgreSQL"""
    stats = db.get_stats()
    
    return jsonify({
        'success': True,
        'database': 'PostgreSQL' if db.conn else 'Demo Mode',
        'stats': stats,
        'tables': ['scans']
    })

@app.route('/api/test/eicar', methods=['GET'])
def test_eicar():
    """Тестовый EICAR файл"""
    # ИСПРАВЛЕННАЯ СТРОКА!
    eicar_content = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, 'eicar_test.txt')
    
    with open(temp_path, 'w') as f:
        f.write(eicar_content)
    
    result = scanner.scan_file(temp_path, 'eicar_test.txt')
    
    # Сохраняем в PostgreSQL
    db.save_scan(result)
    
    # Удаляем временный файл
    os.remove(temp_path)
    
    return jsonify(result)

# ================== ЗАПУСК СЕРВЕРА ==================
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔥 DBT ANTIVIRUS BACKEND v2.0")
    print("="*60)
    print("🌐 API сервер запущен: http://localhost:5000")
    print("🗄️  База данных: PostgreSQL")
    print("📁  Имя БД: dbt antivirus")
    print("📊 API эндпоинты:")
    print("   GET  /              - Документация")
    print("   GET  /api/status    - Статус сервера")
    print("   POST /api/scan      - Сканирование файла")
    print("   GET  /api/history   - История из PostgreSQL")
    print("   GET  /api/stats     - Статистика")
    print("="*60)
    print("💡 Для остановки: Ctrl+C")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)