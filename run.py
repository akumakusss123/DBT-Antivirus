import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    print("\n" + "="*60)
    print(" DBT ANTIVIRUS BACKEND v2.0")
    print("="*60)
    print("🌐 API сервер запущен: http://localhost:5000")
    print("📊 API эндпоинты:")
    print("   POST /api/scan     - Сканирование файла")
    print("   GET  /api/status   - Статус сервера")
    print("   GET  /api/history  - История сканирований")
    print("   GET  /api/stats    - Статистика")
    print("   GET  /api/test/eicar - Тестовый EICAR файл")
    print("="*60)
    print("💡 Для остановки: Ctrl+C")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=port, debug=True)