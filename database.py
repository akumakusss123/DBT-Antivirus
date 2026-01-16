# database.py - УЛУЧШЕННАЯ БАЗА ДАННЫХ POSTGRESQL
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from datetime import datetime, timedelta
import hashlib
import json
import os

class AdvancedDatabase:
    """Улучшенная база данных с расширенными функциями"""
    
    def __init__(self, host="localhost", database="xxx", 
                 user="postgres", password="xxx", port="5432"):
        self.host = host
        self.database = database
        self.user = user
        self.password = password
        self.port = port
        self.conn = None
        self.connect()
    
    def connect(self):
        """Подключение к PostgreSQL"""
        try:
            # Пробуем подключиться к существующей БД
            self.conn = psycopg2.connect(
                host=self.host,
                database=self.database,
                user=self.user,
                password=self.password,
                port=self.port
            )
            self.conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            print(f"✅ Подключено к PostgreSQL: {self.database}")
            self.init_advanced_tables()
            return True
        except psycopg2.OperationalError as e:
            print(f"⚠️ База данных не найдена. Создаем новую...")
            return self.create_database()
        except Exception as e:
            print(f"❌ Ошибка подключения: {e}")
            return False
    
    def create_database(self):
        """Создание новой базы данных"""
        try:
            # Подключаемся к postgres для создания БД
            temp_conn = psycopg2.connect(
                host=self.host,
                database="postgres",
                user=self.user,
                password=self.password,
                port=self.port
            )
            temp_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cursor = temp_conn.cursor()
            
            # Создаем БД
            cursor.execute(f"CREATE DATABASE {self.database}")
            print(f"📦 Создана база данных: {self.database}")
            cursor.close()
            temp_conn.close()
            
            # Подключаемся к новой БД
            self.conn = psycopg2.connect(
                host=self.host,
                database=self.database,
                user=self.user,
                password=self.password,
                port=self.port
            )
            self.conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            
            # Инициализируем таблицы
            self.init_advanced_tables()
            return True
            
        except Exception as e:
            print(f"❌ Ошибка создания БД: {e}")
            return False
    
    def init_advanced_tables(self):
        """Создание улучшенной структуры таблиц"""
        cursor = self.conn.cursor()
        
        # 1. Таблица пользователей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE,
                password_hash VARCHAR(255),
                role VARCHAR(20) DEFAULT 'user',
                avatar_url TEXT,
                settings JSONB DEFAULT '{"theme": "dark", "notifications": true}',
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 2. Таблица файлов (основная)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                original_name VARCHAR(255) NOT NULL,
                stored_name VARCHAR(100) UNIQUE NOT NULL,
                file_hash VARCHAR(64) UNIQUE NOT NULL,
                file_size BIGINT NOT NULL,
                file_type VARCHAR(50),
                mime_type VARCHAR(100),
                uploader_id INTEGER REFERENCES users(id),
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expiration_date TIMESTAMP,
                download_count INTEGER DEFAULT 0,
                metadata JSONB DEFAULT '{}',
                INDEX idx_file_hash (file_hash),
                INDEX idx_upload_date (upload_date DESC)
            )
        ''')
        
        # 3. Таблица сканирований
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                file_id INTEGER REFERENCES files(id),
                scanner_type VARCHAR(20) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                result JSONB NOT NULL,
                threat_level INTEGER DEFAULT 0,
                detection_count INTEGER DEFAULT 0,
                engine_count INTEGER DEFAULT 0,
                malicious_engines TEXT[],
                scan_duration FLOAT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                INDEX idx_scans_file_id (file_id),
                INDEX idx_scans_status (status),
                INDEX idx_scans_threat (threat_level DESC)
            )
        ''')
        
        # 4. Таблица угроз
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                type VARCHAR(50) NOT NULL,
                severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 10),
                description TEXT,
                signature TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP,
                detection_count INTEGER DEFAULT 1,
                INDEX idx_threats_severity (severity DESC),
                INDEX idx_threats_name (name)
            )
        ''')
        
        # 5. Таблица детекций
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id),
                threat_id INTEGER REFERENCES threats(id),
                engine_name VARCHAR(50) NOT NULL,
                detection_name VARCHAR(100),
                confidence FLOAT CHECK (confidence BETWEEN 0 AND 1),
                details JSONB,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_detections_scan (scan_id),
                INDEX idx_detections_threat (threat_id)
            )
        ''')
        
        # 6. Таблица статистики (агрегированные данные)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id SERIAL PRIMARY KEY,
                date DATE UNIQUE NOT NULL,
                total_scans INTEGER DEFAULT 0,
                clean_files INTEGER DEFAULT 0,
                threats_found INTEGER DEFAULT 0,
                top_threats JSONB,
                avg_scan_time FLOAT,
                user_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 7. Таблица настроек системы
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key VARCHAR(50) PRIMARY KEY,
                value TEXT NOT NULL,
                data_type VARCHAR(20) DEFAULT 'string',
                category VARCHAR(30),
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by INTEGER REFERENCES users(id)
            )
        ''')
        
        # 8. Таблица квот пользователей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_quotas (
                user_id INTEGER PRIMARY KEY REFERENCES users(id),
                max_file_size BIGINT DEFAULT 104857600, -- 100 MB
                max_files_per_day INTEGER DEFAULT 100,
                max_concurrent_scans INTEGER DEFAULT 5,
                current_daily_usage INTEGER DEFAULT 0,
                last_reset_date DATE DEFAULT CURRENT_DATE,
                INDEX idx_quotas_usage (current_daily_usage DESC)
            )
        ''')
        
        # Вставляем начальные настройки
        initial_settings = [
            ('max_upload_size', '33554432', 'integer', 'uploads', 'Максимальный размер загружаемого файла (32MB)'),
            ('scan_timeout', '300', 'integer', 'scanning', 'Таймаут сканирования в секундах'),
            ('retention_days', '30', 'integer', 'storage', 'Дней хранения файлов'),
            ('clamav_enabled', 'true', 'boolean', 'scanners', 'Включить ClamAV сканер'),
            ('virustotal_enabled', 'true', 'boolean', 'scanners', 'Включить VirusTotal'),
            ('notification_emails', 'true', 'boolean', 'notifications', 'Отправлять email уведомления'),
            ('daily_scan_limit', '1000', 'integer', 'limits', 'Лимит сканирований в день')
        ]
        
        for key, value, data_type, category, description in initial_settings:
            cursor.execute('''
                INSERT INTO system_settings (key, value, data_type, category, description)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (key) DO NOTHING
            ''', (key, value, data_type, category, description))
        
        # Создаем демо-пользователя
        cursor.execute('''
            INSERT INTO users (username, email, role, settings)
            VALUES ('admin', 'admin@dbt-antivirus.local', 'admin', 
                    '{"theme": "dark", "notifications": true, "language": "ru"}')
            ON CONFLICT (username) DO NOTHING
        ''')
        
        self.conn.commit()
        cursor.close()
        print("✅ Улучшенная структура БД создана")
        
        # Создаем представления для удобства
        self.create_views()
    
    def create_views(self):
        """Создание SQL-представлений"""
        cursor = self.conn.cursor()
        
        # Представление для детальной статистики
        cursor.execute('''
            CREATE OR REPLACE VIEW scan_stats_view AS
            SELECT 
                DATE(s.started_at) as scan_date,
                COUNT(*) as total_scans,
                SUM(CASE WHEN s.threat_level > 0 THEN 1 ELSE 0 END) as threats_found,
                AVG(s.scan_duration) as avg_duration,
                ARRAY_AGG(DISTINCT t.name) as top_threats
            FROM scans s
            LEFT JOIN detections d ON s.id = d.scan_id
            LEFT JOIN threats t ON d.threat_id = t.id
            WHERE s.completed_at IS NOT NULL
            GROUP BY DATE(s.started_at)
            ORDER BY scan_date DESC
        ''')
        
        # Представление для пользовательской активности
        cursor.execute('''
            CREATE OR REPLACE VIEW user_activity_view AS
            SELECT 
                u.username,
                u.role,
                COUNT(f.id) as files_uploaded,
                COUNT(s.id) as scans_performed,
                MAX(s.started_at) as last_scan,
                COALESCE(SUM(f.file_size), 0) as total_upload_size
            FROM users u
            LEFT JOIN files f ON u.id = f.uploader_id
            LEFT JOIN scans s ON f.id = s.file_id
            GROUP BY u.id, u.username, u.role
            ORDER BY scans_performed DESC
        ''')
        
        # Представление для угроз по дням
        cursor.execute('''
            CREATE OR REPLACE VIEW daily_threats_view AS
            SELECT 
                DATE(s.completed_at) as threat_date,
                t.name as threat_name,
                t.severity,
                COUNT(*) as detection_count
            FROM scans s
            JOIN detections d ON s.id = d.scan_id
            JOIN threats t ON d.threat_id = t.id
            WHERE s.threat_level > 0
            GROUP BY DATE(s.completed_at), t.name, t.severity
            ORDER BY threat_date DESC, detection_count DESC
        ''')
        
        self.conn.commit()
        cursor.close()
        print("✅ SQL-представления созданы")
    
    # ========== МЕТОДЫ ДЛЯ РАБОТЫ С ДАННЫМИ ==========
    
    def save_file_metadata(self, filename, file_hash, size, file_type, uploader_id=None):
        """Сохранение метаданных файла"""
        cursor = self.conn.cursor()
        stored_name = f"{file_hash[:16]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        cursor.execute('''
            INSERT INTO files 
            (original_name, stored_name, file_hash, file_size, file_type, uploader_id, upload_date)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (filename, stored_name, file_hash, size, file_type, uploader_id, datetime.now()))
        
        file_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        return file_id
    
    def save_scan_result(self, file_id, scanner_type, result):
        """Сохранение результата сканирования"""
        cursor = self.conn.cursor()
        
        threat_level = result.get('threat_level', 0)
        detection_count = result.get('detection_count', 0)
        engine_count = result.get('engine_count', 0)
        malicious_engines = result.get('malicious_engines', [])
        scan_duration = result.get('scan_duration', 0)
        
        cursor.execute('''
            INSERT INTO scans 
            (file_id, scanner_type, status, result, threat_level, 
             detection_count, engine_count, malicious_engines, scan_duration, completed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            file_id, scanner_type, 'completed', 
            Json(result), threat_level, detection_count, 
            engine_count, malicious_engines, scan_duration, datetime.now()
        ))
        
        scan_id = cursor.fetchone()[0]
        
        # Сохраняем детекции
        detections = result.get('detections', [])
        for detection in detections:
            threat_name = detection.get('threat_name')
            engine_name = detection.get('engine_name')
            
            # Находим или создаем угрозу
            cursor.execute('''
                SELECT id FROM threats WHERE name = %s
            ''', (threat_name,))
            
            threat_row = cursor.fetchone()
            if threat_row:
                threat_id = threat_row[0]
                cursor.execute('''
                    UPDATE threats 
                    SET detection_count = detection_count + 1, last_seen = %s
                    WHERE id = %s
                ''', (datetime.now(), threat_id))
            else:
                cursor.execute('''
                    INSERT INTO threats (name, type, severity, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                ''', (
                    threat_name,
                    detection.get('type', 'unknown'),
                    detection.get('severity', 5),
                    datetime.now(),
                    datetime.now()
                ))
                threat_id = cursor.fetchone()[0]
            
            # Сохраняем детекцию
            cursor.execute('''
                INSERT INTO detections 
                (scan_id, threat_id, engine_name, detection_name, confidence, details)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                scan_id,
                threat_id,
                engine_name,
                detection.get('detection_name'),
                detection.get('confidence', 0.0),
                Json(detection.get('details', {}))
            ))
        
        # Обновляем статистику за день
        self.update_daily_stats()
        
        self.conn.commit()
        cursor.close()
        return scan_id
    
    def update_daily_stats(self):
        """Обновление дневной статистики"""
        cursor = self.conn.cursor()
        today = datetime.now().date()
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN threat_level > 0 THEN 1 ELSE 0 END) as threats
            FROM scans 
            WHERE DATE(started_at) = %s
        ''', (today,))
        
        stats = cursor.fetchone()
        
        cursor.execute('''
            INSERT INTO statistics (date, total_scans, threats_found)
            VALUES (%s, %s, %s)
            ON CONFLICT (date) 
            DO UPDATE SET 
                total_scans = EXCLUDED.total_scans,
                threats_found = EXCLUDED.threats_found,
                updated_at = CURRENT_TIMESTAMP
        ''', (today, stats[0] or 0, stats[1] or 0))
        
        self.conn.commit()
        cursor.close()
    
    def get_dashboard_stats(self):
        """Получение статистики для дашборда"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        # Общая статистика
        cursor.execute('''
            SELECT 
                COUNT(*) as total_scans,
                COUNT(DISTINCT file_hash) as unique_files,
                COUNT(DISTINCT uploader_id) as active_users,
                COALESCE(SUM(file_size), 0) as total_data_size
            FROM files
        ''')
        general_stats = cursor.fetchone()
        
        # Статистика по угрозам
        cursor.execute('''
            SELECT 
                COUNT(*) as total_threats,
                AVG(severity) as avg_severity,
                MAX(severity) as max_severity
            FROM threats
        ''')
        threat_stats = cursor.fetchone()
        
        # Статистика за последние 7 дней
        cursor.execute('''
            SELECT 
                date,
                total_scans,
                threats_found,
                ROUND(CAST(threats_found AS DECIMAL) / NULLIF(total_scans, 0) * 100, 2) as threat_percentage
            FROM statistics 
            WHERE date >= CURRENT_DATE - INTERVAL '7 days'
            ORDER BY date
        ''')
        weekly_stats = cursor.fetchall()
        
        # Топ угроз
        cursor.execute('''
            SELECT 
                name,
                severity,
                detection_count,
                last_seen
            FROM threats 
            ORDER BY detection_count DESC 
            LIMIT 10
        ''')
        top_threats = cursor.fetchall()
        
        cursor.close()
        
        return {
            'general': dict(general_stats),
            'threats': dict(threat_stats),
            'weekly': weekly_stats,
            'top_threats': top_threats,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_scan_history(self, limit=50, offset=0, filters=None):
        """Получение истории сканирований с фильтрами"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        query = '''
            SELECT 
                s.id,
                f.original_name as filename,
                f.file_hash,
                f.file_size,
                s.scanner_type,
                s.status,
                s.threat_level,
                s.detection_count,
                s.engine_count,
                s.started_at,
                s.completed_at,
                s.scan_duration,
                u.username as uploader,
                ARRAY_AGG(DISTINCT d.detection_name) as detections
            FROM scans s
            JOIN files f ON s.file_id = f.id
            LEFT JOIN users u ON f.uploader_id = u.id
            LEFT JOIN detections d ON s.id = d.scan_id
        '''
        
        conditions = []
        params = []
        
        if filters:
            if filters.get('threat_level'):
                conditions.append("s.threat_level >= %s")
                params.append(filters['threat_level'])
            if filters.get('date_from'):
                conditions.append("DATE(s.started_at) >= %s")
                params.append(filters['date_from'])
   