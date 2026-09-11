# Daemon secops
#!/usr/bin/env python3
import os
import sys
import time
import re
import json
import socket
import ipaddress
import subprocess
import urllib.request
import urllib.parse
from collections import defaultdict

CONFIG_FILE = os.getenv("SENTINEL_CONFIG", "/opt/sentinel/config.json")


def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"[КРИТИЧЕСКАЯ ОШИБКА] Файл конфигурации не найден: {CONFIG_FILE}")
        sys.exit(1)
    with open(CONFIG_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def init_nftables():
    commands = [
        "add table inet sentinel",
        "add set inet sentinel blacklist { type ipv4_addr; flags timeout; }",
        "add chain inet sentinel input { type filter hook input priority -10; policy accept; }",
    ]
    for cmd in commands:
        subprocess.run(["nft", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    check_rule = subprocess.run(
        ["nft", "list", "chain", "inet", "sentinel", "input"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if "@blacklist drop" not in check_rule.stdout:
        subprocess.run(
            ["nft", "add", "rule", "inet", "sentinel", "input", "ip", "saddr", "@blacklist", "counter", "drop"],
            check=True
        )


def is_ip_whitelisted(ip_str, whitelist_networks):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net_str in whitelist_networks:
            if ip_obj in ipaddress.ip_network(net_str, strict=False):
                return True
    except ValueError:
        return True
    return False


def ban_ip_nftables(ip_str, duration):
    cmd = f"add element inet sentinel blacklist {{ {ip_str} timeout {duration} }}"
    result = subprocess.run(["nft", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.returncode == 0


def send_telegram_alert(token, chat_id, ip_str, count, duration, reason):
    hostname = socket.gethostname()
    text = (
        f"🚨 *Инцидент безопасности (SOAR Sentinel)*\n\n"
        f"🖥 *Хост:* `{hostname}`\n"
        f"⛔ *Заблокирован адрес:* `{ip_str}`\n"
        f"⚠️ *Причина:* {reason}\n"
        f"🔢 *Число попыток:* {count}\n"
        f"⏱ *Срок блокировки:* {duration}\n"
        f"🛡 *Подсистема:* `nftables (set: blacklist)`"
    )

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown"
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as response:
            pass
    except Exception as error:
        print(f"[ОШИБКА ОПОВЕЩЕНИЯ] Не удалось отправить сообщение в Telegram: {error}", file=sys.stderr)


def follow_file(file_path):
    while not os.path.exists(file_path):
        time.sleep(1)
    
    current_file = open(file_path, "r", encoding="utf-8", errors="ignore")
    current_file.seek(0, os.SEEK_END)
    current_inode = os.fstat(current_file.fileno()).st_ino

    while True:
        line = current_file.readline()
        if line:
            yield line
        else:
            time.sleep(0.2)
            try:
                new_inode = os.stat(file_path).st_ino
                if new_inode != current_inode:
                    current_file.close()
                    current_file = open(file_path, "r", encoding="utf-8", errors="ignore")
                    current_inode = new_inode
            except FileNotFoundError:
                pass


def main():
    config = load_config()
    init_nftables()

    log_path = config.get("log_file", "/var/log/auth.log")
    threshold = config.get("ban_threshold", 5)
    find_time = config.get("find_time_seconds", 300)
    ban_duration = config.get("ban_duration", "24h")
    bot_token = config.get("telegram_bot_token")
    chat_id = config.get("telegram_chat_id")
    whitelist = config.get("whitelist_networks", [])

    failed_patterns = [
        re.compile(r"Failed password for (?:invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+) port"),
        re.compile(r"Invalid user \S+ from (\d+\.\d+\.\d+\.\d+) port"),
        re.compile(r"Connection closed by authenticating user \S+ (\d+\.\d+\.\d+\.\d+) port \d+ \[preauth\]"),
        re.compile(r"Did not receive identification string from (\d+\.\d+\.\d+\.\d+)")
    ]

    history = defaultdict(list)
    banned_ips = set()

    print(f"[СТАРТ] Sentinel запущен. Мониторинг файла: {log_path}")

    for line in follow_file(log_path):
        current_time = time.time()
        detected_ip = None
        attack_reason = "Множественные ошибки аутентификации SSH"

        for pattern in failed_patterns:
            match = pattern.search(line)
            if match:
                detected_ip = match.group(1)
                if "identification string" in line:
                    attack_reason = "Сканирование сетевых портов (портскан)"
                break

        if not detected_ip:
            continue

        if is_ip_whitelisted(detected_ip, whitelist):
            continue

        if detected_ip in banned_ips:
            continue

        # Фильтрация устаревших попыток по окну времени
        history[detected_ip] = [t for t in history[detected_ip] if current_time - t <= find_time]
        history[detected_ip].append(current_time)

        if len(history[detected_ip]) >= threshold:
            banned_ips.add(detected_ip)
            success = ban_ip_nftables(detected_ip, ban_duration)

            if success:
                print(f"[БЛОКИРОВКА] Сетевой адрес {detected_ip} заблокирован на срок {ban_duration}")
                send_telegram_alert(
                    token=bot_token,
                    chat_id=chat_id,
                    ip_str=detected_ip,
                    count=len(history[detected_ip]),
                    duration=ban_duration,
                    reason=attack_reason
                )
            else:
                print(f"[ОШИБКА] Не удалось добавить адрес {detected_ip} в nftables", file=sys.stderr)


if __name__ == "__main__":
    main()
