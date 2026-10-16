import csv
from pathlib import Path


def export_to_csv(output_path, results):
    """
    Экспорт результатов AuthWatch в CSV.

    results — словарь с результатами анализа (self.last_results из app.py).
    Все секции пишутся в один CSV, разделённые пустыми строками.
    """
    output_path = Path(output_path)

    suspicious_ips = results.get("suspicious_ips", {}) or {}
    attempts_by_ip = results.get("attempts_by_ip", {}) or {}
    distributed = results.get("distributed_attacks", {}) or {}
    compromises = results.get("compromises", []) or []
    threshold = results.get("threshold", "")

    with output_path.open("w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.writer(csv_file, delimiter=";")

        # ==================================================
        # 1. Общая информация
        # ==================================================
        writer.writerow(["AuthWatch — результаты анализа"])
        writer.writerow(["Дата анализа", results.get("timestamp", "")])
        writer.writerow(["Файл журнала", results.get("file", "")])
        writer.writerow(["Всего событий", results.get("events", 0)])
        writer.writerow(["Некорректных строк",
                         results.get("invalid_lines", 0)])
        writer.writerow(["Порог попыток", threshold])
        writer.writerow(["Временное окно (сек.)",
                         results.get("window_seconds", "")])
        writer.writerow([
            "Подозрительных IP",
            len(suspicious_ips),
        ])
        writer.writerow([
            "Распределённых атак",
            len(distributed),
        ])
        writer.writerow([
            "Скомпрометированных аккаунтов",
            len(compromises),
        ])
        writer.writerow([])

        # ==================================================
        # 1.5. Скомпрометированные аккаунты (если есть)
        # ==================================================
        if compromises:
            writer.writerow(["⚠ СКОМПРОМЕТИРОВАННЫЕ АККАУНТЫ"])
            writer.writerow([
                "Пользователь",
                "IP успешного входа",
                "Неудачных попыток до успеха",
                "Разных IP",
                "Все IP атаки",
                "Первая неудача",
                "Успешный вход",
                "Длительность (сек.)",
                "Статус",
            ])
            for c in sorted(compromises,
                            key=lambda x: x.get("failed_attempts", 0),
                            reverse=True):
                writer.writerow([
                    c.get("user", ""),
                    c.get("success_ip", ""),
                    c.get("failed_attempts", 0),
                    c.get("distinct_ips", 0),
                    ", ".join(c.get("ips", [])),
                    c.get("first_failure", ""),
                    c.get("success_time", ""),
                    c.get("span_seconds", 0),
                    "CRITICAL",
                ])
            writer.writerow([])

        # ==================================================
        # 2. Распределённые атаки (если есть)
        # ==================================================
        if distributed:
            writer.writerow(["⚠ РАСПРЕДЕЛЁННЫЕ АТАКИ"])
            writer.writerow([
                "Пользователь",
                "IP-адресов",
                "Всего попыток",
                "IP-адреса",
                "Первая попытка",
                "Последняя попытка",
                "Статус",
            ])
            for user, info in sorted(
                distributed.items(),
                key=lambda item: item[1].get("attempts", 0),
                reverse=True,
            ):
                ips = info.get("ips", [])
                writer.writerow([
                    user,
                    info.get("ip_count", len(ips)),
                    info.get("attempts", 0),
                    ", ".join(ips),
                    info.get("first_seen", ""),
                    info.get("last_seen", ""),
                    "CRITICAL",
                ])
            writer.writerow([])

        # ==================================================
        # 3. Таблица подозрительных IP
        # ==================================================
        writer.writerow(["ПОДОЗРИТЕЛЬНЫЕ IP-АДРЕСА"])
        writer.writerow([
            "IP-адрес",
            "Максимум неудачных попыток в окне",
            "Статус",
        ])
        if suspicious_ips:
            for ip, attempts in sorted(
                suspicious_ips.items(),
                key=lambda item: item[1],
                reverse=True,
            ):
                writer.writerow([
                    ip,
                    attempts,
                    "Подозрительная активность",
                ])
        else:
            writer.writerow([
                "—",
                0,
                "Подозрительные IP не обнаружены",
            ])
        writer.writerow([])

        # ==================================================
        # 4. Все IP с попытками (детальный список)
        # ==================================================
        if attempts_by_ip:
            writer.writerow(["ВСЕ IP С НЕУДАЧНЫМИ ПОПЫТКАМИ"])
            writer.writerow([
                "IP-адрес",
                "Макс. попыток в окне",
                "Подозрительный?",
                "Порог",
            ])
            for ip, attempts in sorted(
                attempts_by_ip.items(),
                key=lambda item: item[1],
                reverse=True,
            ):
                writer.writerow([
                    ip,
                    attempts,
                    "ДА" if ip in suspicious_ips else "нет",
                    threshold,
                ])

    return output_path