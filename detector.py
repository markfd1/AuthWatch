from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
import ipaddress
import math
import re


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"(?P<status>FAILED|SUCCESS) "
    r"user=(?P<user>\S+) "
    r"ip=(?P<ip>\S+)$"
)

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

DISTRIBUTED_IP_THRESHOLD = 3
COMPROMISE_THRESHOLD = 3            # сколько неудач перед успехом = тревога
COMPROMISE_WINDOW_SECONDS = 300     # в пределах 5 минут


def analyze_log(
    file_path,
    threshold=5,
    window_seconds=60,
    distributed_ip_threshold=DISTRIBUTED_IP_THRESHOLD,
    compromise_threshold=COMPROMISE_THRESHOLD,
    compromise_window_seconds=COMPROMISE_WINDOW_SECONDS,
):
    """
    Анализ журнала аутентификации.

    Возвращает 6 значений:
        total_events, attempts_by_ip, suspicious_ips,
        distributed_attacks, compromises, invalid_lines.
    """

    # ---- Валидация ----
    if (isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or threshold < 1):
        raise ValueError("threshold must be a positive integer")

    if (isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or not math.isfinite(window_seconds)
            or window_seconds <= 0):
        raise ValueError("window_seconds must be a positive finite number")

    if (isinstance(distributed_ip_threshold, bool)
            or not isinstance(distributed_ip_threshold, int)
            or distributed_ip_threshold < 2):
        raise ValueError(
            "distributed_ip_threshold must be an integer >= 2")

    if (isinstance(compromise_threshold, bool)
            or not isinstance(compromise_threshold, int)
            or compromise_threshold < 1):
        raise ValueError(
            "compromise_threshold must be a positive integer")

    if (isinstance(compromise_window_seconds, bool)
            or not isinstance(compromise_window_seconds, (int, float))
            or compromise_window_seconds <= 0):
        raise ValueError(
            "compromise_window_seconds must be a positive number")

    file_path = Path(file_path)
    window = timedelta(seconds=window_seconds)
    comp_window = timedelta(seconds=compromise_window_seconds)

    events = []
    invalid_lines = 0

    # ---- Чтение и валидация ----
    with file_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            line = line.strip()
            if not line:
                continue

            match = LOG_PATTERN.fullmatch(line)
            if not match:
                invalid_lines += 1
                continue

            event = match.groupdict()

            try:
                timestamp = datetime.strptime(
                    event["timestamp"], TIMESTAMP_FORMAT)
            except ValueError:
                invalid_lines += 1
                continue

            try:
                ip = str(ipaddress.ip_address(event["ip"]))
            except ValueError:
                invalid_lines += 1
                continue

            events.append(
                (timestamp, event["status"], event["user"], ip))

    events.sort(key=lambda e: e[0])

    # ---- Счётчики ----
    attempts_by_ip = defaultdict(deque)
    failed_by_user = defaultdict(deque)         # для распределённых
    failed_history = defaultdict(deque)         # для компрометации (user -> [(ts, ip)])

    max_attempts = {}
    suspicious_ips = {}
    distributed_raw = {}
    compromises = []

    for timestamp, status, user, ip in events:
        # ============ FAILED ============
        if status == "FAILED":
            # --- 1. Обычный брутфорс одного IP ---
            ip_attempts = attempts_by_ip[ip]
            while ip_attempts and timestamp - ip_attempts[0] > window:
                ip_attempts.popleft()
            ip_attempts.append(timestamp)
            current = len(ip_attempts)

            if current > max_attempts.get(ip, 0):
                max_attempts[ip] = current

            if current >= threshold:
                if current > suspicious_ips.get(ip, 0):
                    suspicious_ips[ip] = current

            # --- 2. Распределённая атака ---
            user_attempts = failed_by_user[user]
            while (user_attempts
                   and timestamp - user_attempts[0][0] > window):
                user_attempts.popleft()
            user_attempts.append((timestamp, ip))

            if len(user_attempts) >= threshold:
                distinct_ips = {ip_ for _, ip_ in user_attempts}
                if len(distinct_ips) >= distributed_ip_threshold:
                    existing = distributed_raw.get(user)
                    if (existing is None
                            or len(user_attempts) > existing["attempts"]):
                        distributed_raw[user] = {
                            "ips": set(distinct_ips),
                            "attempts": len(user_attempts),
                            "first_seen": user_attempts[0][0],
                            "last_seen": timestamp,
                        }

            # --- 3. История неудач для детекции компрометации ---
            failed_history[user].append((timestamp, ip))

        # ============ SUCCESS ============
        else:
            history = failed_history.get(user)
            if not history:
                continue

            # Оставляем только неудачи за последние comp_window секунд
            recent = [(ts, ip_) for ts, ip_ in history
                      if timestamp - ts <= comp_window]
            # Обновляем историю (чистим старые)
            while history and timestamp - history[0][0] > comp_window:
                history.popleft()

            if len(recent) >= compromise_threshold:
                ips_involved = sorted({ip_ for _, ip_ in recent})
                compromises.append({
                    "user": user,
                    "success_ip": ip,
                    "failed_attempts": len(recent),
                    "distinct_ips": len(ips_involved),
                    "ips": ips_involved,
                    "first_failure": recent[0][0].strftime(TIMESTAMP_FORMAT),
                    "success_time": timestamp.strftime(TIMESTAMP_FORMAT),
                    "span_seconds": int(
                        (timestamp - recent[0][0]).total_seconds()),
                })

    # ---- Финализация распределённых ----
    distributed_attacks = {}
    for user, info in distributed_raw.items():
        distributed_attacks[user] = {
            "ips": sorted(info["ips"]),
            "ip_count": len(info["ips"]),
            "attempts": info["attempts"],
            "first_seen": info["first_seen"].strftime(TIMESTAMP_FORMAT),
            "last_seen": info["last_seen"].strftime(TIMESTAMP_FORMAT),
        }

    return (
        len(events),
        dict(max_attempts),
        suspicious_ips,
        distributed_attacks,
        compromises,
        invalid_lines,
    )