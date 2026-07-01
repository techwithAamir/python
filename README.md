# 🛡️ Endpoint Security Assessment Tool

> A Python-based Windows endpoint security assessment tool developed for cybersecurity education and authorized security research. The application demonstrates multiple endpoint monitoring and system information collection techniques using a multithreaded architecture.

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![OS](https://img.shields.io/badge/OS-Windows-0078D6?logo=windows)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Architecture](https://img.shields.io/badge/Architecture-Multithreading-orange)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)

---

# 📖 Overview

The **Endpoint Security Assessment Tool** is a Python application designed to demonstrate endpoint monitoring and information gathering techniques in a controlled and authorized environment.

The project combines multiple system assessment modules—including keyboard event monitoring, clipboard inspection, screenshot capture, webcam image capture, host information collection, and IP-based geolocation—into a single multithreaded application.

This project was built to gain practical experience in endpoint security, understand common attack techniques, and study how defensive solutions such as Endpoint Detection and Response (EDR) systems can identify these behaviors.

---

# 🚀 Features

- ⌨️ Keyboard Activity Monitoring
- 📋 Clipboard Data Collection
- 📸 Desktop Screenshot Capture
- 📷 Webcam Image Capture
- 🌍 Public IP & Geolocation Lookup
- 💻 System Information Collection
- 📄 JSON-Based Logging
- ⚡ Multithreaded Execution
- 🔒 Thread-Safe Logging

---

# 🛠️ Technologies Used

- Python
- OpenCV
- Pynput
- Pillow (PIL)
- Requests
- PyWin32
- Threading
- Socket
- Platform
- JSON

---

# 📂 Project Structure

```
Endpoint Security Assessment Tool/
│
├── main.py
└── README.md
```

---

# 🏗️ Working Flow

```
                 Start Application
                         │
                         ▼
          Collect System Information
                         │
       ┌─────────────────┼─────────────────┐
       │                 │                 │
       ▼                 ▼                 ▼
 Screenshot       Clipboard Data      Webcam Capture
       │                 │                 │
       └─────────────────┼─────────────────┘
                         │
                         ▼
           Keyboard Listener Starts
                         │
                         ▼
          Store Keystrokes in Buffer
                         │
                         ▼
      Save Logs Every 10 Seconds
```

---

# ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/techwithAamir/Endpoint-Security-Assessment-Tool.git
```

Navigate into the project

```bash
cd Endpoint-Security-Assessment-Tool
```

Install the required dependencies

```bash
pip install opencv-python pynput pillow pywin32 requests
```

Run the application

```bash
python main.py
```

---

# 📚 Skills Demonstrated

- Python Programming
- Cybersecurity Research
- Endpoint Monitoring
- Multithreading
- Thread Synchronization
- Windows API Interaction
- Host Enumeration
- File Handling
- JSON Processing
- Defensive Security Concepts

---

# 🎯 Learning Outcomes

This project provided hands-on experience with:

- Endpoint assessment techniques
- Windows endpoint monitoring
- Keyboard event capture
- Clipboard monitoring
- Screenshot acquisition
- Webcam interaction
- Public IP intelligence
- Geolocation lookup
- Concurrent programming
- Thread synchronization
- Secure file handling

---


# ⚠️ Disclaimer

This project was developed **solely for educational purposes, cybersecurity research, and authorized security testing**.

It demonstrates endpoint monitoring concepts to help students, researchers, and security professionals understand endpoint compromise techniques and strengthen defensive security practices.

**Do not execute this software on any system without explicit authorization.**

The author assumes no responsibility for misuse of this project.

---

# 👨‍💻 Author

**MD AAMIR**


⭐ If you found this project useful, consider giving it a **Star**.
