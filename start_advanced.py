# start_advanced.py - Запуск улучшенной версии
import subprocess
import sys
import os

def install_requirements():
    """Установка зависимостей"""
    requirements = [
        'flask',
        'flask-cors',
        'psycopg2-binary',
        'python-dotenv',
        'requests'
    ]
    
    print("📦 Устанавливаем зависимости...")
    for package in requirements:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f" ✅ {package}")
        except:
            print(f" ❌ {package}")

def check_postgresql():
    """Проверка PostgreSQL"""
    print("🔍 Проверяем PostgreSQL...")
    try:
        import psycopg2
        conn = psycopg2.connect(
            host="localhost",
            database="postgres",
            user="postgres",
            password="akunkumi",
            port="5432"
        )
        conn.close()
        print("✅ PostgreSQL работает")
        return True
    except Exception as e:
        print(f"❌ Ошибка PostgreSQL: {e}")
        print("\n🔧 Решение:")
        print("1. Запустите pgAdmin")
        print("2. Убедитесь что пароль: xxx")
        print("3. Или измените настройки в database.py")
        return False

def main():
    """Основная функция"""
    print("\n" + "="*60)
    print("🚀 ЗАПУСК DBT ANTIVIRUS ADVANCED")
    print("="*60)
    
    # Установка зависимостей
    install_requirements()
    
    # Проверка PostgreSQL
    if not check_postgresql():
        print("⚠️ Продолжаем в DEMO режиме...")
    
    # Запуск бэкенда
    print("\n▶️ Запуск улучшенного бэкенда...")
    os.system("python backend_advanced.py")

if __name__ == "__main__":
    main()