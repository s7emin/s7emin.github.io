document.addEventListener("DOMContentLoaded", () => {
    const phoneInput = document.getElementById("phone");
    const passwordInput = document.getElementById("password");
    const ipInput = document.getElementById("ip");
    const portInput = document.getElementById("port");
    const speedInput = document.getElementById("speed");

    const phonePattern = /^\+7\d{10}$/;
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const validSpeeds = ["2400", "4800", "9600", "19200", "38400", "57600", "115200"];

    // Функция для проверки и вывода ошибок
    const validateField = (field, pattern, errorMessage, errorElement) => {
        if (!pattern.test(field.value)) {
            field.classList.add("error");
            errorElement.textContent = errorMessage;
            errorElement.style.display = "inline-block"; // Показываем ошибку
        } else {
            field.classList.remove("error");
            errorElement.textContent = "";
            errorElement.style.display = "none"; // Скрываем ошибку
        }
    };

    // Проверка номера телефона
    phoneInput.addEventListener('input', () => {
        validateField(phoneInput, phonePattern, "Номер телефона должен быть в формате +7XXXXXXXXXX", document.getElementById("phone-error"));
    });

    // Проверка IP
    ipInput.addEventListener('input', () => {
        validateField(ipInput, ipPattern, "Введите корректный IP-адрес (например, 192.168.1.1)", document.getElementById("ip-error"));
    });

    // Проверка порта
    portInput.addEventListener('input', () => {
        const port = parseInt(portInput.value, 10);
        if (port < 1 || port > 65535) {
            portInput.classList.add("error");
            document.getElementById("port-error").textContent = "Порт должен быть в пределах от 1 до 65535";
            document.getElementById("port-error").style.display = "inline-block";
        } else {
            portInput.classList.remove("error");
            document.getElementById("port-error").textContent = "";
            document.getElementById("port-error").style.display = "none";
        }
    });

    // Проверка скорости
    speedInput.addEventListener('change', () => {
        if (!validSpeeds.includes(speedInput.value)) {
            speedInput.classList.add("error");
            document.getElementById("speed-error").textContent = "Выберите корректную скорость";
            document.getElementById("speed-error").style.display = "inline-block";
        } else {
            speedInput.classList.remove("error");
            document.getElementById("speed-error").textContent = "";
            document.getElementById("speed-error").style.display = "none";
        }
    });

    // Загружаем данные из локального хранилища
    const loadStoredData = () => {
        const storedData = JSON.parse(localStorage.getItem("configData"));
        if (storedData) {
            phoneInput.value = storedData.phone || "+7";
            passwordInput.value = storedData.password || "usr.cn";
            ipInput.value = storedData.ip || "";
            portInput.value = storedData.port || 1;
            speedInput.value = storedData.speed || "9600";
        }
    };

    // Сохраняем данные в локальное хранилище
    const saveDataToLocalStorage = () => {
        const configData = {
            phone: phoneInput.value,
            password: passwordInput.value,
            ip: ipInput.value,
            port: portInput.value,
            speed: speedInput.value,
        };
        localStorage.setItem("configData", JSON.stringify(configData));
    };

    // Генерация QR-кода
    const generateQRCode = () => {
        const phone = phoneInput.value;
        const password = passwordInput.value;
        const ip = ipInput.value;
        const port = portInput.value;
        const speed = speedInput.value;

        const smsContent = `${password}#AT+SOCKA="TCP","${ip}",${port};AT+UART=${speed},"NONE",8,1,"NONE";AT+RSTIM=60000;AT+HEARTEN="off";AT+REGTP="IMEI";AT+REGEN="on";AT+S`;
        const smsLink = `smsto:${phone}?body=${encodeURIComponent(smsContent)}`;

        QRCode.toCanvas(document.getElementById("qrCodeCanvas"), smsLink, { width: 200 }, (error) => {
            if (error) console.error(error);
        });
    };

    // Слушатели событий для каждого поля
    phoneInput.addEventListener("input", () => {
        saveDataToLocalStorage();
        generateQRCode();
    });

    passwordInput.addEventListener("input", () => {
        saveDataToLocalStorage();
        generateQRCode();
    });

    ipInput.addEventListener("input", () => {
        saveDataToLocalStorage();
        generateQRCode();
    });

    portInput.addEventListener("input", () => {
        saveDataToLocalStorage();
        generateQRCode();
    });

    speedInput.addEventListener("change", () => {
        saveDataToLocalStorage();
        generateQRCode();
    });

    // Инициализация
    loadStoredData();
    generateQRCode();
});
