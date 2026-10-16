
import json
from datetime import datetime, timezone
from pathlib import Path


def save_report(
    output_path,
    total_events,
    suspicious_ips,
    invalid_lines,
    threshold,
    window_seconds,
    attempts_by_ip=None,
    distributed_attacks=None,
    compromises=None,
):
    """
    Сохраняет JSON-отчёт по результатам анализа.

    attempts_by_ip и distributed_attacks — опциональные.
    Если переданы, попадут в отчёт отдельными секциями.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # ---- Секция: подозрительные IP ----
    alerts = [
        {
            "ip": ip,
            "failed_attempts": attempts,
            "severity": _severity(attempts, threshold),
        }
        for ip, attempts in sorted(
            suspicious_ips.items(),
            key=lambda item: item[1],
            reverse=True,
        )
    ]

    # ---- Секция: все IP с попытками ----
    all_ips_section = []
    if attempts_by_ip:
        for ip, attempts in sorted(
            attempts_by_ip.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            all_ips_section.append({
                "ip": ip,
                "max_attempts_in_window": attempts,
                "is_suspicious": ip in suspicious_ips,
            })

    # ---- Секция: распределённые атаки ----
    distributed_section = []
    if distributed_attacks:
        for user, info in sorted(
            distributed_attacks.items(),
            key=lambda item: item[1].get("attempts", 0),
            reverse=True,
        ):
            distributed_section.append({
                "target_user": user,
                "attempts": info.get("attempts", 0),
                "ip_count": info.get("ip_count", len(info.get("ips", []))),
                "ips": list(info.get("ips", [])),
                "first_seen": info.get("first_seen", ""),
                "last_seen": info.get("last_seen", ""),
                "severity": "CRITICAL",
            })
    # ---- Секция: скомпрометированные аккаунты ----
    compromises_section = []
    if compromises:
        for c in sorted(compromises,
                        key=lambda x: x.get("failed_attempts", 0),
                        reverse=True):
            compromises_section.append({
                "user": c.get("user", ""),
                "success_ip": c.get("success_ip", ""),
                "failed_attempts": c.get("failed_attempts", 0),
                "distinct_ips": c.get("distinct_ips", 0),
                "ips": c.get("ips", []),
                "first_failure": c.get("first_failure", ""),
                "success_time": c.get("success_time", ""),
                "span_seconds": c.get("span_seconds", 0),
                "severity": "CRITICAL",
            })

    # ---- Сборка отчёта ----
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "events_analyzed": total_events,
            "invalid_lines": invalid_lines,
            "alerts_count": len(alerts),
            "distributed_attacks_count": len(distributed_section),
            "compromised_accounts_count": len(compromises_section),
        },
        "detection_settings": {
            "failed_attempts_threshold": threshold,
            "time_window_seconds": window_seconds,
        },
        "compromised_accounts": compromises_section,
        "distributed_attacks": distributed_section,
        "alerts": alerts,
        "all_ips_observed": all_ips_section,
    }

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    return output_path


def _severity(attempts, threshold):
    """Оценка серьёзности по числу попыток относительно порога."""
    if threshold <= 0:
        return "HIGH"
    ratio = attempts / threshold
    if ratio >= 4:
        return "CRITICAL"
    if ratio >= 2:
        return "HIGH"
    return "MEDIUM"


if __name__ == "__main__":
    print("REPORTER STARTED")

    path = Path(__file__).parent / "reports" / "test.json"

    saved_path = save_report(
        output_path=path,
        total_events=10,
        suspicious_ips={"192.168.1.100": 5, "10.0.0.5": 25},
        invalid_lines=0,
        threshold=5,
        window_seconds=60,
        attempts_by_ip={
            "192.168.1.100": 5,
            "10.0.0.5": 25,
            "10.0.0.6": 2,
        },
        distributed_attacks={
            "mark": {
                "ips": ["198.51.100.77", "198.51.100.88", "198.51.100.99"],
                "ip_count": 3,
                "attempts": 9,
                "first_seen": "2026-10-14 11:00:10",
                "last_seen": "2026-10-14 11:00:26",
            }
        },
    )

    print("FILE CREATED:", saved_path.resolve())
    print("FILE EXISTS:", saved_path.exists())