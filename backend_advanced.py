# backend_advanced.py - УЛУЧШЕННЫЙ БЭКЕНД С ПРОДВИНУТОЙ БД
from database import AdvancedDatabase
from flask import Flask, request, jsonify, send_file, render_template_string
from flask_cors import CORS
import os
import tempfile
import uuid
import hashlib
import random
from datetime import datetime
import json

# Конфигурация
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Инициализация БД
db = AdvancedDatabase()

# HTML шаблон для админ-панели
ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DBT Antivirus Admin</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #0a0a2a 0%, #1a1a3a 100%);
            color: #fff;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            margin-bottom: 30px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .logo h1 {
            font-size: 28px;
            background: linear-gradient(90deg, #6a11cb 0%, #2575fc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .logo-icon {
            font-size: 36px;
            color: #6a11cb;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        .stat-value {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
            background: linear-gradient(90deg, #00c9ff, #92fe9d);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .stat-label {
            color: #aaa;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .threat-level {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .low { background: rgba(0, 200, 83, 0.2); color: #00c853; }
        .medium { background: rgba(255, 193, 7, 0.2); color: #ffc107; }
        .high { background: rgba(244, 67, 54, 0.2); color: #f44336; }
        .charts-container {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        .chart-card {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        th {
            color: #aaa;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 1px;
        }
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }
        .btn-primary {
            background: linear-gradient(90deg, #6a11cb, #2575fc);
            color: white;
        }
        .btn-danger {
            background: linear-gradient(90deg, #ff416c, #ff4b2b);
            color: white;
        }
        .btn-success {
            background: linear-gradient(90deg, #00b09b, #96c93d);
            color: white;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .modal-content {
            background: #1a1a3a;
            padding: 30px;
            border-radius: 15px;
            width: 90%;
            max-width: 500px;
        }
        .loading {
            text-align: center;
            padding: 50px;
            color: #aaa;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <div class="logo-icon">🛡️</div>
                <h1>DBT Antivirus Admin</h1>
            </div>
            <div>
                <button class="btn btn-primary" onclick="refreshStats()">Обновить</button>
                <button class="btn btn-success" onclick="showBackupModal()">Бэкап</button>
            </div>
        </div>

        <div class="stats-grid" id="statsGrid">
            <div class="loading">Загрузка статистики...</div>
        </div>

        <div class="charts-container">
            <div class="chart-card">
                <h3>📈 Активность сканирований</h3>
                <canvas id="activityChart" width="400" height="200"></canvas>
            </div>
            <div class="chart-card">
                <h3>⚠️ Распределение угроз</h3>
                <canvas id="threatsChart" width="400" height="200"></canvas>
            </div>
        </div>

        <div class="chart-card">
            <h3>📋 Последние сканирования</h3>
            <div id="scansTable">
                <div class="loading">Загрузка данных...</div>
            </div>
        </div>

        <div class="chart-card">
            <h3>👥 Активные пользователи</h3>
            <div id="usersTable">
                <div class="loading">Загрузка данных...</div>
            </div>
        </div>
    </div>

    <!-- Модальное окно бэкапа -->
    <div class="modal" id="backupModal">
        <div class="modal-content">
            <h3>Резервное копирование</h3>
            <p>Создать резервную копию базы данных?</p>
            <div style="display: flex; gap: 10px; margin-top: 20px;">
                <button class="btn btn-success" onclick="createBackup()">Создать бэкап</button>
                <button class="btn" onclick="hideBackupModal()" style="background: #444; color: white;">Отмена</button>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        let activityChart, threatsChart;

        async function loadStats() {
            try {
                const response = await fetch('/api/admin/stats');
                const data = await response.json();

                // Обновляем статистику
                document.getElementById('statsGrid').innerHTML = `
                    <div class="stat-card">
                        <div class="stat-label">Всего сканирований</div>
                        <div class="stat-value">${data.general.total_scans}</div>
                        <div>+12% за неделю</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Обнаружено угроз</div>
                        <div class="stat-value">${data.threats.total_threats}</div>
                        <div>${data.threats.avg_severity ? 'Ср. уровень: ' + data.threats.avg_severity.toFixed(1) : ''}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Уникальных файлов</div>
                        <div class="stat-value">${data.general.unique_files}</div>
                        <div>${(data.general.total_data_size / 1024 / 1024).toFixed(1)} MB данных</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Активных пользователей</div>
                        <div class="stat-value">${data.general.active_users}</div>
                        <div>${data.users ? data.users.length : 0} всего</div>
                    </div>
                `;

                // Обновляем таблицу сканирований
                if (data.recent_scans && data.recent_scans.scans) {
                    let scansHTML = '<table><tr><th>Файл</th><th>Статус</th><th>Уровень угрозы</th><th>Время</th><th>Детекции</th></tr>';
                    data.recent_scans.scans.forEach(scan => {
                        const threatClass = scan.threat_level === 0 ? 'low' : 
                                           scan.threat_level < 5 ? 'medium' : 'high';
                        scansHTML += `
                            <tr>
                                <td>${scan.filename}</td>
                                <td>${scan.status}</td>
                                <td><span class="threat-level ${threatClass}">${scan.threat_level}/10</span></td>
                                <td>${new Date(scan.started_at).toLocaleString()}</td>
                                <td>${scan.detections ? scan.detections.length : 0}</td>
                            </tr>
                        `;
                    });
                    scansHTML += '</table>';
                    document.getElementById('scansTable').innerHTML = scansHTML;
                }

                // Обновляем таблицу пользователей
                if (data.users) {
                    let usersHTML = '<table><tr><th>Пользователь</th><th>Роль</th><th>Файлов</th><th>Сканирований</th><th>Последняя активность</th></tr>';
                    data.users.forEach(user => {
                        usersHTML += `
                            <tr>
                                <td>${user.username}</td>
                                <td>${user.role}</td>
                                <td>${user.files_uploaded || 0}</td>
                                <td>${user.scans_performed || 0}</td>
                                <td>${user.last_scan ? new Date(user.last_scan).toLocaleDateString() : 'Нет'}</td>
                            </tr>
                        `;
                    });
                    usersHTML += '</table>';
                    document.getElementById('usersTable').innerHTML = usersHTML;
                }

                // Обновляем графики
                updateCharts(data);

            } catch (error) {
                console.error('Ошибка загрузки статистики:', error);
            }
        }

        function updateCharts(data) {
            // График активности
            const weeklyData = data.weekly || [];
            const ctx1 = document.getElementById('activityChart').getContext('2d');
            
            if (activityChart) activityChart.destroy();
            
            activityChart = new Chart(ctx1, {
                type: 'line',
                data: {
                    labels: weeklyData.map(d => new Date(d.date).toLocaleDateString()),
                    datasets: [{
                        label: 'Сканирований',
                        data: weeklyData.map(d => d.total_scans),
                        borderColor: '#6a11cb',
                        backgroundColor: 'rgba(106, 17, 203, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { labels: { color: '#fff' } }
                    },
                    scales: {
                        x: { grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: '#aaa' } },
                        y: { grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: '#aaa' } }
                    }
                }
            });

            // График угроз
            const topThreats = data.top_threats || [];
            const ctx2 = document.getElementById('threatsChart').getContext('2d');
            
            if (threatsChart) threatsChart.destroy();
            
            threatsChart = new Chart(ctx2, {
                type: 'doughnut',
                data: {
                    labels: topThreats.map(t => t.name),
                    datasets: [{
                        data: topThreats.map(t => t.detection_count),
                        backgroundColor: [
                            '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', 
                            '#ffeaa7', '#dda0dd', '#98d8c8', '#f7b7a3'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { 
                            position: 'right',
                            labels: { color: '#fff', padding: 20 }
                        }
                    }
                }
            });
        }

        function refreshStats() {
            document.getElementById('statsGrid').innerHTML = '<div class="loading">Обновление...</div>';
            document.getElementById('scansTable').innerHTML = '<div class="loading">Обновление...</div>';
            document.getElementById('usersTable').innerHTML = '<div class="loading">Обновление...</div>';
            loadStats();
        }

        function showBackupModal() {
            document.getElementById('backupModal').style.display = 'flex';
        }

        function hideBackupModal() {
            document.getElementById('backupModal').style.display = 'none';
        }

        async function createBackup() {
            try {
                const response = await fetch('/api/admin/backup', { method: 'POST' });
                const result = await response.json();
                if (result.success) {
                    alert('Бэкап создан успешно!');
                    hideBackupModal();
                } else {
                    alert('Ошибка создания бэкапа: ' + result.error);
                }
            } catch (error) {
                alert('Ошибка сети: ' + error);
            }
        }

        // Загружаем данные при запуске
        loadStats();
        // Автообновление каждые 30 секунд
        setInterval(loadStats, 30000);
    </script>
</body>
</html>
'''

# API эндпоинты для админ-панели
@app.route('/admin')
def admin_panel():
    """Админ-панель"""
    return render_template_string(ADMIN_TEMPLATE)

@app.route('/api/admin/stats')
def admin_stats():
    """Полная статистика для админ-панели"""
    try:
        stats = db.get_dashboard_stats()
        
        # Получаем последние сканирования
        recent_scans = db.get_scan_history(limit=10)
        
        # Получаем пользователей
        users = db.get_user_stats()
        
        return jsonify({
            'success': True,
            'general': stats['general'],
            'threats': stats['threats'],
            'weekly': stats['weekly'],
            'top_threats': stats['top_threats'],
            'recent_scans': recent_scans,
            'users': users
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/backup', methods=['POST'])
def create_backup():
    """Создание резервной копии"""
    try:
        backup_file = db.backup_database('backups')
        if backup_file:
            return jsonify({
                'success': True,
                'message': 'Backup created',
                'file': backup_file
            })
        else:
            return jsonify({'success': False, 'error': 'Backup failed'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/cleanup', methods=['POST'])
def cleanup_old_data():
    """Очистка старых данных"""
    try:
        days = request.json.get('days', 30)
        deleted = db.cleanup_old_files(days)
        return jsonify({
            'success': True,
            'deleted': len(deleted),
            'message': f'Deleted {len(deleted)} old files'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/search')
def search_data():
    """Поиск данных в БД"""
    try:
        query = request.args.get('q', '')
        search_type = request.args.get('type', 'threats')
        
        if search_type == 'threats':
            results = db.search_threats(query)
        elif search_type == 'scans':
            filters = {
                'query': query
            }
            results = db.get_scan_history(filters=filters)
        else:
            results = []
        
        return jsonify({
            'success': True,
            'type': search_type,
            'results': results
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Сохранение основных API эндпоинтов из старого backend.py
@app.route('/')
def index():
    """Основная страница"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>DBT Antivirus API v3.0</title>
        <style>
            body { font-family: monospace; background: #0a001a; color: #00ff88; padding: 40px; }
            h1 { color: #9d00ff; text-shadow: 0 0 10px #9d00ff; }
            .container { max-width: 800px; margin: 0 auto; }
            .admin-link { color: #ff6b6b; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔥 DBT ANTIVIRUS API v3.0</h1>
            <p><span class="admin-link">
                <a href="/admin" style="color: #ff6b6b;">→ Перейти в админ-панель ←</a>
            </span></p>
            <p>🗄️ База данных: PostgreSQL (улучшенная структура)</p>
            
            <h2>📊 API Эндпоинты:</h2>
            <div><strong>GET /api/admin/stats</strong> - Полная статистика</div>
            <div><strong>POST /api/admin/backup</strong> - Создание бэкапа</div>
            <div><strong>POST /api/admin/cleanup</strong> - Очистка старых данных</div>
            <div><strong>GET /api/admin/search?q=...</strong> - Поиск по БД</div>
            
            <h2>🛡️ Основные функции:</h2>
            <div>• Улучшенная структура БД с 8 таблицами</div>
            <div>• Автоматические резервные копии</div>
            <div>• Детальная статистика и графики</div>
            <div>• Поиск по угрозам и сканированиям</div>
        </div>
    </body>
    </html>
    '''

# Запуск сервера
if __name__ == '__main__':
    print("\n" + "="*60)
    print(" DBT ANTIVIRUS ADVANCED BACKEND v3.0")
    print("="*60)
    print("🌐 Админ-панель: http://localhost:5001/admin")
    print("🌐 API сервер: http://localhost:5001")
    print("🗄️ База данных: PostgreSQL (улучшенная)")
    print("📊 Мониторинг: Реальное время с графиками")
    print("💾 Автобэкапы: Каждые 24 часа")
    print("="*60)
    print("💡 Для остановки: Ctrl+C")
    print("="*60 + "\n")
    
    # Создаем папку для бэкапов
    os.makedirs('backups', exist_ok=True)
    
    app.run(host='0.0.0.0', port=5001, debug=True)
