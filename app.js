// ===== КОНФИГУРАЦИЯ =====
const API_URL = 'http://localhost:5000/api';
let currentFile = null;
let currentHash = null;
let scanResults = [];
// ===== ПРОВЕРКА POSTGRESQL =====
async function checkPostgreSQL() {
    try {
        const response = await fetch(`${API_URL}/status`);
        const data = await response.json();
        
        // Обновляем статус PostgreSQL
        const postgresStatus = document.createElement('div');
        postgresStatus.className = 'postgres-status';
        postgresStatus.innerHTML = `
            <div style="background: ${data.connected ? '#44ff4422' : '#ff444422'}; 
                       border: 1px solid ${data.connected ? '#44ff44' : '#ff4444'}; 
                       padding: 10px 20px; 
                       border-radius: 25px; 
                       margin: 10px 0;
                       display: inline-flex;
                       align-items: center;
                       gap: 10px;">
                🗄️ ${data.connected ? 'POSTGRESQL: CONNECTED' : 'POSTGRESQL: DEMO MODE'}
                <i class="fas fa-${data.connected ? 'database' : 'exclamation-triangle'}"></i>
            </div>
        `;
        
        // Добавляем после заголовка
        const header = document.querySelector('.cyber-header');
        if (!document.querySelector('.postgres-status')) {
            header.appendChild(postgresStatus);
        }
        
        return data.connected;
    } catch (error) {
        console.log('PostgreSQL check failed:', error);
        return false;
    }
}

// Добавь в конец функции DOMContentLoaded:
document.addEventListener('DOMContentLoaded', async () => {
    console.log('🚀 DBT Antivirus v2.0 initialized');
    
    // Проверка API статуса
    await checkAPIStatus();
    
    // Проверка PostgreSQL
    await checkPostgreSQL();
    
    // Остальной код...
});

// ===== ИНИЦИАЛИЗАЦИЯ =====
document.addEventListener('DOMContentLoaded', async () => {
    console.log('🚀 DBT Antivirus v2.0 initialized');
    
    // Проверка API статуса
    await checkAPIStatus();
    
    // Инициализация матрицы
    initMatrix();
    
    // Инициализация графиков
    initChart();
    
    // Настройка drag & drop
    setupDragAndDrop();
    
    // Настройка загрузки файлов
    setupFileUpload();
    
    // Загрузка истории
    await loadScanHistory();
});

// ===== MATRIX BACKGROUND =====
function initMatrix() {
    const canvas = document.getElementById('matrix');
    const ctx = canvas.getContext('2d');
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const chars = "01abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$+-*/=%\"'#&_(),.;:?!\\|{}<>[]^~";
    const charArray = chars.split("");
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = [];
    
    for (let i = 0; i < columns; i++) {
        drops[i] = Math.floor(Math.random() * canvas.height / fontSize);
    }
    
    function drawMatrix() {
        ctx.fillStyle = "rgba(5, 0, 17, 0.04)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = "#9d00ff";
        ctx.font = `${fontSize}px 'Share Tech Mono'`;
        
        for (let i = 0; i < drops.length; i++) {
            const text = charArray[Math.floor(Math.random() * charArray.length)];
            const x = i * fontSize;
            const y = drops[i] * fontSize;
            
            ctx.fillStyle = "#9d00ff";
            ctx.fillText(text, x, y);
            
            ctx.fillStyle = "#00e1ff";
            ctx.fillText(text, x + 1, y + 1);
            
            if (y > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }
    
    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    
    window.addEventListener('resize', resizeCanvas);
    setInterval(drawMatrix, 50);
}

// ===== API STATUS CHECK =====
async function checkAPIStatus() {
    try {
        const response = await fetch(`${API_URL}/status`);
        const data = await response.json();
        
        const indicator = document.getElementById('apiStatusIndicator');
        const statusText = document.getElementById('apiStatusText');
        
        if (data.status === 'online') {
            indicator.className = 'status-indicator online';
            statusText.textContent = 'API ONLINE';
            showNotification('Система активна', 'success');
        } else {
            indicator.className = 'status-indicator';
            statusText.textContent = 'API OFFLINE';
            showNotification('Ошибка подключения к API', 'error');
        }
    } catch (error) {
        console.error('API check failed:', error);
        document.getElementById('apiStatusText').textContent = 'API ERROR';
        showNotification('Не удалось подключиться к серверу', 'error');
    }
}

// ===== DRAG & DROP =====
function setupDragAndDrop() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        
        if (e.dataTransfer.files.length) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });
    
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFileUpload(e.target.files[0]);
        }
    });
}

// ===== FILE UPLOAD =====
function setupFileUpload() {
    document.getElementById('scanBtn').addEventListener('click', startScan);
}

async function handleFileUpload(file) {
    if (!file) return;
    
    // Проверяем размер файла (макс 32 МБ для VirusTotal Free)
    if (file.size > 32 * 1024 * 1024) {
        showNotification('Файл слишком большой (макс 32 МБ)', 'error');
        return;
    }
    
    currentFile = file;
    
    // Обновляем информацию о файле
    document.getElementById('fileName').textContent = file.name;
    document.getElementById('fileSize').textContent = formatFileSize(file.size);
    
    // Вычисляем SHA-256 хеш
    await calculateFileHash(file);
    
    // Показываем панель информации о файле
    document.getElementById('fileInfo').classList.add('active');
    
    showNotification(`Файл "${file.name}" загружен`, 'success');
}

// ===== SHA-256 HASH CALCULATION =====
async function calculateFileHash(file) {
    showNotification('Вычисление хеша SHA-256...', 'info');
    
    try {
        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        currentHash = hashHex;
        document.getElementById('fileHash').textContent = hashHex;
        
        showNotification('Хеш вычислен успешно', 'success');
    } catch (error) {
        console.error('Hash calculation error:', error);
        showNotification('Ошибка вычисления хеша', 'error');
    }
}

// ===== START SCAN =====
async function startScan() {
    if (!currentFile) {
        showNotification('Сначала выберите файл', 'warning');
        return;
    }
    
    const scanBtn = document.getElementById('scanBtn');
    const scanProgress = document.getElementById('scanProgress');
    
    // Блокируем кнопку
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> СКАНИРУЕТСЯ...';
    
    // Показываем прогресс
    scanProgress.classList.add('active');
    
    // Создаем FormData для отправки файла
    const formData = new FormData();
    formData.append('file', currentFile);
    
    // Симуляция прогресса
    simulateProgress();
    
    try {
        // Отправляем файл на бэкенд
        console.log('📤 Отправка файла на сервер:', currentFile.name);
        
        const response = await fetch(`${API_URL}/scan`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        console.log('✅ Результат сканирования:', result);
        
        // Сохраняем результат
        scanResults.unshift(result);
        
        // Обновляем таблицу
        updateResultsTable();
        
        // Обновляем график
        updateChart();
        
        // Обновляем статистику
        updateStats();
        
        showNotification('Сканирование завершено', 'success');
        
    } catch (error) {
        console.error('❌ Ошибка сканирования:', error);
        showNotification('Ошибка сканирования: ' + error.message, 'error');
        
        // Добавляем результат с ошибкой
        const errorResult = {
            filename: currentFile.name,
            hash: currentHash || 'error',
            timestamp: new Date().toISOString(),
            status: 'ERROR',
            virustotal: { detected: false, error: error.message },
            clamav: { detected: false, error: 'Not scanned' }
        };
        
        scanResults.unshift(errorResult);
        updateResultsTable();
        
    } finally {
        // Восстанавливаем кнопку
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fas fa-play"></i> НАЧАТЬ СКАНИРОВАНИЕ';
        
        // Скрываем прогресс
        scanProgress.classList.remove('active');
        document.querySelector('.progress-fill').style.width = '0%';
        document.getElementById('scanPercent').textContent = '0%';
    }
}

// ===== PROGRESS SIMULATION =====
function simulateProgress() {
    const progressFill = document.querySelector('.progress-fill');
    const scanStatus = document.getElementById('scanStatus');
    const scanPercent = document.getElementById('scanPercent');
    
    const steps = [
        { percent: 10, text: 'Инициализация сканера...' },
        { percent: 25, text: 'Вычисление контрольных сумм...' },
        { percent: 40, text: 'Отправка в VirusTotal...' },
        { percent: 60, text: 'Анализ 70+ антивирусов...' },
        { percent: 75, text: 'Проверка в ClamAV...' },
        { percent: 90, text: 'Эвристический анализ...' },
        { percent: 100, text: 'Формирование отчета...' }
    ];
    
    steps.forEach((step, index) => {
        setTimeout(() => {
            progressFill.style.width = `${step.percent}%`;
            scanStatus.textContent = step.text;
            scanPercent.textContent = `${step.percent}%`;
        }, index * 1000);
    });
}

// ===== UPDATE RESULTS TABLE =====
function updateResultsTable() {
    const tbody = document.getElementById('resultsBody');
    
    // Очищаем таблицу, кроме заглушки
    const placeholder = tbody.querySelector('.placeholder');
    if (placeholder) {
        tbody.removeChild(placeholder);
    }
    
    // Добавляем последние 10 результатов
    const recentResults = scanResults.slice(0, 10);
    
    tbody.innerHTML = '';
    
    recentResults.forEach(result => {
        const row = document.createElement('tr');
        
        // Определяем статус
        let statusClass = 'status-clean';
        let statusText = 'ЧИСТЫЙ';
        
        if (result.status === 'ERROR') {
            statusClass = 'status-threat';
            statusText = 'ОШИБКА';
        } else if (result.virustotal?.detected || result.clamav?.detected) {
            statusClass = 'status-threat';
            statusText = 'УГРОЗА';
        } else if (result.status === 'suspicious') {
            statusClass = 'status-suspicious';
            statusText = 'ПОДОЗРИТЕЛЬНЫЙ';
        }
        
        // VirusTotal результаты
        const vtDetections = result.virustotal?.detections || 0;
        const vtTotal = result.virustotal?.total || 70;
        const vtText = result.virustotal?.error ? 'Ошибка' : `${vtDetections}/${vtTotal}`;
        
        // ClamAV результаты
        const clamavResult = result.clamav?.detected ? 'Обнаружен' : (result.clamav?.error || 'Чистый');
        
        // Время
        const time = new Date(result.timestamp).toLocaleTimeString();
        
        row.innerHTML = `
            <td><span class="status-badge ${statusClass}">${statusText}</span></td>
            <td>${result.filename}</td>
            <td>${vtText}</td>
            <td>${clamavResult}</td>
            <td>${time}</td>
        `;
        
        tbody.appendChild(row);
    });
}

// ===== CHART INITIALIZATION =====
let threatChart = null;

function initChart() {
    const ctx = document.getElementById('threatChart').getContext('2d');
    
    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Чистые', 'Подозрительные', 'Вредоносные'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    'rgba(0, 255, 157, 0.7)',
                    'rgba(255, 204, 0, 0.7)',
                    'rgba(255, 51, 102, 0.7)'
                ],
                borderColor: [
                    '#00ff9d',
                    '#ffcc00',
                    '#ff3366'
                ],
                borderWidth: 2,
                hoverOffset: 15
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.label}: ${context.parsed}`;
                        }
                    }
                }
            },
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });
}

function updateChart() {
    if (!threatChart) return;
    
    const clean = scanResults.filter(r => !r.virustotal?.detected && !r.clamav?.detected).length;
    const suspicious = scanResults.filter(r => r.status === 'suspicious').length;
    const malicious = scanResults.filter(r => r.virustotal?.detected || r.clamav?.detected).length;
    
    threatChart.data.datasets[0].data = [clean, suspicious, malicious];
    threatChart.update();
    
    // Обновляем цифры статистики
    document.getElementById('cleanStat').textContent = clean;
    document.getElementById('suspiciousStat').textContent = suspicious;
    document.getElementById('maliciousStat').textContent = malicious;
}

// ===== LOAD SCAN HISTORY =====
async function loadScanHistory() {
    try {
        const response = await fetch(`${API_URL}/history`);
        const history = await response.json();
        
        if (history && Array.isArray(history)) {
            scanResults = history;
            updateResultsTable();
            updateChart();
            updateStats();
        }
    } catch (error) {
        console.error('Ошибка загрузки истории:', error);
    }
}

// ===== UPDATE STATS =====
function updateStats() {
    const totalScans = scanResults.length;
    const cleanScans = scanResults.filter(r => !r.virustotal?.detected && !r.clamav?.detected).length;
    const threatScans = scanResults.filter(r => r.virustotal?.detected || r.clamav?.detected).length;
    
    // Здесь можно обновить статистику на дашборде
    console.log(`📊 Статистика: Всего - ${totalScans}, Чистые - ${cleanScans}, Угрозы - ${threatScans}`);
}

// ===== UTILITY FUNCTIONS =====
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Б';
    const k = 1024;
    const sizes = ['Б', 'КБ', 'МБ', 'ГБ'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    const title = notification.querySelector('#notificationTitle');
    const msg = notification.querySelector('#notificationMessage');
    const icon = notification.querySelector('i');
    
    // Устанавливаем иконку в зависимости от типа
    switch(type) {
        case 'success':
            icon.className = 'fas fa-check-circle';
            notification.className = 'notification success';
            title.textContent = 'Успешно';
            break;
        case 'error':
            icon.className = 'fas fa-exclamation-circle';
            notification.className = 'notification error';
            title.textContent = 'Ошибка';
            break;
        case 'warning':
            icon.className = 'fas fa-exclamation-triangle';
            notification.className = 'notification warning';
            title.textContent = 'Внимание';
            break;
        default:
            icon.className = 'fas fa-info-circle';
            notification.className = 'notification';
            title.textContent = 'Информация';
    }
    
    msg.textContent = message;
    notification.classList.add('show');
    
    // Автоматическое скрытие через 5 секунд
    setTimeout(() => {
        notification.classList.remove('show');
    }, 5000);
}

function copyHash() {
    const hashElement = document.getElementById('fileHash');
    const hash = hashElement.textContent;
    
    navigator.clipboard.writeText(hash).then(() => {
        showNotification('Хеш скопирован в буфер обмена', 'success');
    }).catch(err => {
        console.error('Ошибка копирования:', err);
        showNotification('Не удалось скопировать хеш', 'error');
    });
}

// ===== TERMINAL FUNCTIONS =====
function showTerminal() {
    document.getElementById('terminalModal').classList.add('active');
}

function hideTerminal() {
    document.getElementById('terminalModal').classList.remove('active');
}

// Экспорт функций для глобального использования
window.copyHash = copyHash;
window.showTerminal = showTerminal;
window.hideTerminal = hideTerminal;