# 🛡️ Endpoint Security Assessment Tool

> A Python-based Windows endpoint monitoring application developed for cybersecurity education and authorized security research. The project demonstrates multiple endpoint data collection techniques in a controlled environment using multithreading.

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-success)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

---

# 📖 Overview

This project was developed to understand how endpoint monitoring techniques work in Windows environments. It combines multiple system monitoring modules into a single multithreaded Python application to simulate common endpoint data collection methods used during cybersecurity research.

The objective is to help students and security professionals understand endpoint compromise vectors and strengthen defensive security practices by studying attacker methodologies in an authorized environment.

---

# 🚀 Features

- ⌨️ Keyboard Activity Monitoring
- 📋 Clipboard Data Collection
- 📸 Automatic Desktop Screenshot Capture
- 📷 Webcam Image Capture
- 🌍 Public IP & Geolocation Lookup
- 💻 System Information Collection
- 📄 JSON-Based System Information Logging
- 🔒 Thread-Safe Logging Using Mutex Locks
- ⚡ Multithreaded Execution

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
Endpoint-Monitor/
│
├── main.py
├── logs.txt
├── clipboard.txt
├── system_info.json
├── screenshot.png
├── webcam_capture.jpg
├── requirements.txt
└── README.md
```

---

# 🏗️ Architecture

```
                 Start Program
                       │
                       ▼
          Collect System Information
                       │
       ┌───────────────┼───────────────┐
       │               │               │
       ▼               ▼               ▼
 Screenshot      Clipboard Log    Webcam Capture
       │               │               │
       └───────────────┼───────────────┘
                       │
                       ▼
          Keyboard Listener Starts
                       │
                       ▼
          Store Keys in Memory Buffer
                       │
                       ▼
      Write Logs Every 10 Seconds
```

---

# 📁 Output Files

| File | Description |
|------|-------------|
| logs.txt | Stores keyboard activity |
| clipboard.txt | Stores clipboard contents |
| screenshot.png | Captured desktop screenshot |
| webcam_capture.jpg | Captured webcam image |
| system_info.json | System information and geolocation |

---

# ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/techwithAamir/Advance_keylogger.git
```

Navigate to the project

```bash
cd Advance_keylogger
```

Install dependencies

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
- Windows API Interaction
- Endpoint Monitoring
- Multithreading
- Thread Synchronization
- Host Enumeration
- File Handling
- JSON Processing
- Defensive Security Concepts
- Cybersecurity Research

---

# 🎯 Learning Outcomes

Through this project, I gained practical experience with:

- Endpoint monitoring techniques
- Windows information gathering
- Keyboard event monitoring
- Clipboard monitoring
- Screenshot acquisition
- Webcam interaction
- Public IP intelligence
- Geolocation lookup
- Concurrent programming using multithreading
- Thread synchronization using locks
- Secure file handling

---

# 🔮 Future Improvements

- AES Encrypted Log Storage
- SQLite Database Integration
- Configurable Monitoring Modules
- HTML Report Generation
- Secure Dashboard
- Network Connection Monitoring
- Process Monitoring
- Cross-Platform Support
- Improved Error Handling
- Plugin-Based Architecture

---

# ⚠️ Disclaimer

This project was created **solely for educational purposes, cybersecurity research, and authorized security testing**.

It demonstrates endpoint monitoring techniques to help students and security professionals understand attacker methodologies and improve defensive security controls.

**Do not execute this software on any system without explicit authorization.**

The author assumes no responsibility for misuse of this project.

---

# 👨‍💻 Author

**MD AAMIR**

🎓 B.Tech Computer Science Engineering (AI & ML)

🔐 Cybersecurity • Ethical Hacking • Python • QA Automation

GitHub: https://github.com/techwithAamir

---

⭐ If you found this project useful, consider giving it a **Star**!
