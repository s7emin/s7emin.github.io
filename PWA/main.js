document.getElementById("saveButton").addEventListener("click", function() {
    let phoneNumber = document.getElementById("phoneNumber").value;
    let password = document.getElementById("password").value || "usr.cn";
    let ipAddress = document.getElementById("ipAddress").value;
    let port = document.getElementById("port").value;
    let speed = document.getElementById("speed").value;

    localStorage.setItem("phoneNumber", phoneNumber);
    localStorage.setItem("password", password);
    localStorage.setItem("ipAddress", ipAddress);
    localStorage.setItem("port", port);
    localStorage.setItem("speed", speed);
});

document.addEventListener("DOMContentLoaded", function() {
    let phoneNumber = localStorage.getItem("phoneNumber");
    let password = localStorage.getItem("password") || "usr.cn";
    let ipAddress = localStorage.getItem("ipAddress");
    let port = localStorage.getItem("port");
    let speed = localStorage.getItem("speed");

    if (phoneNumber) {
        document.getElementById("phoneNumber").value = phoneNumber;
    }
    if (password) {
        document.getElementById("password").value = password;
    }
    if (ipAddress) {
        document.getElementById("ipAddress").value = ipAddress;
    }
    if (port) {
        document.getElementById("port").value = port;
    }
    if (speed) {
        document.getElementById("speed").value = speed;
    }
});

document.getElementById("generateSMS").addEventListener("click", function() {
    let phoneNumber = document.getElementById("phoneNumber").value;
    if (!phoneNumber) {
        alert("Пожалуйста, введите номер телефона.");
        return;
    }

    let password = document.getElementById("password").value || "usr.cn";
    let ipAddress = document.getElementById("ipAddress").value;
    let port = document.getElementById("port").value;
    let speed = document.getElementById("speed").value;

    let smsBody = `Пароль: ${password}, IP: ${ipAddress}, Порт: ${port}, Скорость: ${speed}`;
    let smsURI = `sms:${phoneNumber}?body=${encodeURIComponent(smsBody)}`;

    window.location.href = smsURI;
});
