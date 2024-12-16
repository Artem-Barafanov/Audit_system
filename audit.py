import os
import time
import json
import syslog
import inotify.adapters
import psutil
import socket
import threading
import tkinter as tk
from tkinter import messagebox
import matplotlib.pyplot as plt
import datetime
import ctypes
import tarfile
from collections import Counter
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Настройки для отправки электронной почты
SMTP_SERVER = "smtp.gmail.com"  # Адрес SMTP-сервера (например, Gmail)
SMTP_PORT = 587  # Порт для TLS
SMTP_USERNAME = "..." 
SMTP_PASSWORD = "..." 
RECIPIENT_EMAIL = "..."


def send_email_notification(subject, body):
    """
    Отправляет уведомление по электронной почте.
    :param subject: Тема письма
    :param body: Тело письма
    """
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = RECIPIENT_EMAIL
        msg['Subject'] = subject

        # Добавляем тело письма
        msg.attach(MIMEText(body, 'plain'))

        # Подключаемся к SMTP-серверу и отправляем письмо
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)

        print("Уведомление отправлено по электронной почте.")
    except Exception as e:
        print(f"Ошибка при отправке уведомления: {e}")


# Функция для регистрации событий
def log_event(event_type, details):
    """
    Регистрирует событие в файле audit.log, отправляет его в системный журнал и уведомляет по электронной почте.
    """
    try:
        timestamp = int(time.time())

        event = {
            "timestamp": timestamp,
            "type": event_type,
            "details": details
        }

        with open("audit.log", "a") as log_file:
            log_file.write(json.dumps(event) + "\n")

        syslog.syslog(syslog.LOG_INFO, json.dumps(event))

        # Отправка уведомления по электронной почте
        subject = f"Событие: {event_type}"
        body = f"Тип события: {event_type}\nДетали: {json.dumps(details, indent=2)}"
        send_email_notification(subject, body)

        rotate_log_file()

        print(f"Событие '{event_type}' зарегистрировано и отправлено.")
    except Exception as e:
        print(f"Ошибка при регистрации события: {e}")


def rotate_log_file():
    """
    Проверяет размер файла audit.log и, если он превышает 10 МБ, создает архив и удаляет оригинальный файл.
    """
    log_file_path = "audit.log"
    if os.path.exists(log_file_path) and os.path.getsize(log_file_path) > 10 * 1024 * 1024:
        archive_name = f"audit_log_{int(time.time())}.tar.gz"
        with tarfile.open(archive_name, "w:gz") as tar:
            tar.add(log_file_path)
        os.remove(log_file_path)


# Мониторинг процессов с использованием ptrace
def monitor_processes_with_ptrace(notification_text):
    libc = ctypes.CDLL("libc.so.6")
    ptrace = libc.ptrace
    ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    ptrace.restype = ctypes.c_int

    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            ptrace(1, proc.pid, None, None)  # PTRACE_TRACEME Выззванный процесс хочет, чтобы его отслеживал другой процесс
            proc.cpu_percent()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        log_event("process_start", {"pid": proc.pid, "name": proc.name(), "user": proc.username()})
        notify_event("process_start", {"pid": proc.pid, "name": proc.name(), "user": proc.username()},
                     notification_text)


# Мониторинг файлов
def monitor_files(notification_text):
    i = inotify.adapters.Inotify() 
    i.add_watch('/path/to/directory')
    for event in i.event_gen(yield_nones=False):
        (_, type_names, path, filename) = event
        log_event("file_change", {"path": path, "filename": filename, "type": type_names})
        notify_event("file_change", {"path": path, "filename": filename, "type": type_names}, notification_text)



def monitor_network(notification_text):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 0))
    s.listen(1)
    log_event("network_operation", {"port": s.getsockname()[1]})
    notify_event("network_operation", {"port": s.getsockname()[1]}, notification_text)



def search_events(event_type=None, user=None, result_text=None):
    with open("audit.log", "r") as log_file:
        for line in log_file:
            event = json.loads(line)
            if event_type and event["type"] != event_type:
                continue
            if user and event["details"].get("user") != user:
                continue
            formatted_time = datetime.datetime.fromtimestamp(event["timestamp"]).strftime('%Y-%m-%d %H:%M:%S')
            result_text.insert(tk.END, f"Time: {formatted_time}, Type: {event['type']}, Details: {event['details']}\n")


def notify_event(event_type, details, notification_text=None):
    if event_type == "suspicious_process":
        notification_text.insert(tk.END, f"Suspicious Process Detected: {json.dumps(details)}\n")
    else:
        notification_text.insert(tk.END, f"Event: {event_type}, Details: {json.dumps(details)}\n")


def generate_report():
    events = []
    with open("audit.log", "r") as log_file:
        for line in log_file:
            events.append(json.loads(line))

    event_types = [event["type"] for event in events]
    event_type_counts = Counter(event_types)

    plt.figure(figsize=(10, 5))
    plt.bar(event_type_counts.keys(), event_type_counts.values())
    plt.xlabel('Тип события')
    plt.ylabel('Количество')
    plt.title('Статистика по типам событий')
    plt.savefig("event_type_stats.png")
    plt.close()

    users = [event["details"].get("user") for event in events if "user" in event["details"]]
    user_counts = Counter(users)

    plt.figure(figsize=(15, 8))
    plt.bar(user_counts.keys(), user_counts.values())
    plt.xlabel('Пользователь')
    plt.ylabel('Количество')
    plt.title('Статистика по пользователям')
    plt.xticks(rotation=45, ha='right') 
    plt.tight_layout()  
    plt.yscale('log') 
    plt.savefig("user_stats.png")
    plt.close()

    with open("report.txt", "w") as report_file:
        report_file.write("Статистика по типам событий:\n")
        for event_type, count in event_type_counts.items():
            report_file.write(f"{event_type}: {count}\n")
        report_file.write("\nСтатистика по пользователям:\n")
        for user, count in user_counts.items():
            report_file.write(f"{user}: {count}\n")


# Аутентификация пользователя
def authenticate_user(password):
    with open("password.txt", "r") as password_file:
        stored_password = password_file.read().strip()
        return password == stored_password


class AuditToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Системный инструмент для аудита системы Linux")

        self.login_frame = tk.Frame(root)
        self.login_frame.pack(pady=10)

        tk.Label(self.login_frame, text="Пароль:").grid(row=0, column=0)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=0, column=1)

        tk.Button(self.login_frame, text="Войти", command=self.login).grid(row=1, columnspan=2, pady=10)

        self.monitor_frame = tk.Frame(root)
        self.monitor_frame.pack(pady=10)

        self.monitor_processes_var = tk.BooleanVar()
        self.monitor_files_var = tk.BooleanVar()
        self.monitor_network_var = tk.BooleanVar()

        tk.Checkbutton(self.monitor_frame, text="Мониторинг процессов", variable=self.monitor_processes_var).pack(
            anchor=tk.W)
        tk.Checkbutton(self.monitor_frame, text="Мониторинг файлов", variable=self.monitor_files_var).pack(anchor=tk.W)
        tk.Checkbutton(self.monitor_frame, text="Мониторинг сетевых операций", variable=self.monitor_network_var).pack(
            anchor=tk.W)

        tk.Button(self.monitor_frame, text="Запустить мониторинг", command=self.start_monitoring).pack(pady=10)

        self.search_frame = tk.Frame(root)
        self.search_frame.pack(pady=10)

        tk.Label(self.search_frame, text="Тип события:").grid(row=0, column=0)
        self.event_type_entry = tk.Entry(self.search_frame)
        self.event_type_entry.grid(row=0, column=1)

        tk.Label(self.search_frame, text="Пользователь:").grid(row=1, column=0)
        self.user_entry = tk.Entry(self.search_frame)
        self.user_entry.grid(row=1, column=1)

        tk.Button(self.search_frame, text="Поиск событий", command=self.search_events_gui).grid(row=2, columnspan=2,
                                                                                                pady=10)

        self.result_text = tk.Text(root, height=10, width=80)
        self.result_text.pack(pady=10)

        self.notification_text = tk.Text(root, height=5, width=80)
        self.notification_text.pack(pady=10)

        tk.Button(root, text="Создать отчет", command=self.generate_report).pack(pady=10)

        self.authenticated = False

    def login(self):
        password = self.password_entry.get()
        if authenticate_user(password):
            self.authenticated = True
            self.login_frame.pack_forget()
            self.monitor_frame.pack()
            self.search_frame.pack()
            self.result_text.pack()
            self.notification_text.pack()
        else:
            messagebox.showerror("Ошибка", "Неверный пароль")

    def check_authentication(self):
        if not self.authenticated:
            messagebox.showerror("Ошибка", "Необходимо ввести верный пароль")
            return False
        return True

    def start_monitoring(self):
        if not self.check_authentication():
            return
        if self.monitor_processes_var.get():
            threading.Thread(target=monitor_processes_with_ptrace, args=(self.notification_text,)).start()
        if self.monitor_files_var.get():
            threading.Thread(target=monitor_files, args=(self.notification_text,)).start()
        if self.monitor_network_var.get():
            threading.Thread(target=monitor_network, args=(self.notification_text,)).start()
        messagebox.showinfo("Мониторинг", "Мониторинг запущен")

    def search_events_gui(self):
        if not self.check_authentication():
            return
        self.result_text.delete(1.0, tk.END) 
        event_type = self.event_type_entry.get()
        user = self.user_entry.get()

        search_events(event_type, user, self.result_text)
        messagebox.showinfo("Поиск событий", "Поиск завершен")

    def generate_report(self):
        if not self.check_authentication():
            return
        generate_report()
        messagebox.showinfo("Отчет", "Отчет создан")


if __name__ == "__main__":
    root = tk.Tk()
    app = AuditToolGUI(root)
    root.mainloop()
