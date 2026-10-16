"""Тесты для модуля detector.py"""

import pytest
from pathlib import Path
from detector import analyze_log


# ============================================================
# Фикстуры — временные лог-файлы
# ============================================================
@pytest.fixture
def bruteforce_log(tmp_path):
    """Один IP, много неудачных попыток."""
    log = tmp_path / "bruteforce.log"
    lines = []
    for i in range(10):
        lines.append(
            f"2026-10-14 10:00:{i:02d} FAILED user=root ip=8.8.8.8"
        )
    log.write_text("\n".join(lines), encoding="utf-8")
    return log


@pytest.fixture
def distributed_log(tmp_path):
    """Три IP атакуют одного пользователя."""
    log = tmp_path / "distributed.log"
    log.write_text(
        "2026-10-14 10:00:01 FAILED user=admin ip=1.1.1.1\n"
        "2026-10-14 10:00:02 FAILED user=admin ip=2.2.2.2\n"
        "2026-10-14 10:00:03 FAILED user=admin ip=3.3.3.3\n"
        "2026-10-14 10:00:04 FAILED user=admin ip=1.1.1.1\n"
        "2026-10-14 10:00:05 FAILED user=admin ip=2.2.2.2\n"
        "2026-10-14 10:00:06 FAILED user=admin ip=3.3.3.3\n",
        encoding="utf-8",
    )
    return log


@pytest.fixture
def compromise_log(tmp_path):
    """Провалы, потом успех — компрометация."""
    log = tmp_path / "compromise.log"
    log.write_text(
        "2026-10-14 10:00:01 FAILED user=bob ip=4.4.4.4\n"
        "2026-10-14 10:00:02 FAILED user=bob ip=4.4.4.4\n"
        "2026-10-14 10:00:03 FAILED user=bob ip=4.4.4.4\n"
        "2026-10-14 10:00:04 FAILED user=bob ip=4.4.4.4\n"
        "2026-10-14 10:00:05 SUCCESS user=bob ip=4.4.4.4\n",
        encoding="utf-8",
    )
    return log


# ============================================================
# ТЕСТЫ: Brute-force
# ============================================================
def test_detects_bruteforce(bruteforce_log):
    events, _, suspicious, _, _, invalid = analyze_log(
        bruteforce_log, threshold=5, window_seconds=60
    )
    assert events == 10
    assert invalid == 0
    assert "8.8.8.8" in suspicious
    assert suspicious["8.8.8.8"] >= 5


def test_bruteforce_below_threshold(tmp_path):
    log = tmp_path / "low.log"
    log.write_text(
        "2026-10-14 10:00:01 FAILED user=a ip=5.5.5.5\n"
        "2026-10-14 10:00:02 FAILED user=a ip=5.5.5.5\n",
        encoding="utf-8",
    )
    _, _, suspicious, _, _, _ = analyze_log(log, threshold=5, window_seconds=60)
    assert "5.5.5.5" not in suspicious


def test_window_respected(tmp_path):
    """Попытки далеко за окном не считаются вместе."""
    log = tmp_path / "window.log"
    log.write_text(
        "2026-10-14 10:00:01 FAILED user=a ip=6.6.6.6\n"
        "2026-10-14 10:00:02 FAILED user=a ip=6.6.6.6\n"
        "2026-10-14 10:00:03 FAILED user=a ip=6.6.6.6\n"
        "2026-10-14 11:00:00 FAILED user=a ip=6.6.6.6\n"
        "2026-10-14 11:00:01 FAILED user=a ip=6.6.6.6\n"
        "2026-10-14 11:00:02 FAILED user=a ip=6.6.6.6\n",
        encoding="utf-8",
    )
    _, _, suspicious, _, _, _ = analyze_log(log, threshold=5, window_seconds=60)
    assert "6.6.6.6" not in suspicious


# ============================================================
# ТЕСТЫ: Distributed attacks
# ============================================================
def test_detects_distributed(distributed_log):
    _, _, _, distributed, _, _ = analyze_log(
        distributed_log, threshold=5, window_seconds=60
    )
    assert "admin" in distributed
    assert distributed["admin"]["ip_count"] == 3
    assert distributed["admin"]["attempts"] == 6


# ============================================================
# ТЕСТЫ: Compromise
# ============================================================
def test_detects_compromise(compromise_log):
    _, _, _, _, compromises, _ = analyze_log(
        compromise_log, threshold=5, window_seconds=60
    )
    assert len(compromises) == 1
    assert compromises[0]["user"] == "bob"
    assert compromises[0]["failed_attempts"] == 4


def test_single_failure_then_success_not_compromise(tmp_path):
    """1 провал + успех — это не компрометация (порог = 3)."""
    log = tmp_path / "single.log"
    log.write_text(
        "2026-10-14 10:00:01 FAILED user=alice ip=7.7.7.7\n"
        "2026-10-14 10:00:02 SUCCESS user=alice ip=7.7.7.7\n",
        encoding="utf-8",
    )
    _, _, _, _, compromises, _ = analyze_log(
        log, threshold=5, window_seconds=60
    )
    assert len(compromises) == 0


# ============================================================
# ТЕСТЫ: Некорректные строки
# ============================================================
def test_invalid_lines_counted(tmp_path):
    log = tmp_path / "mixed.log"
    log.write_text(
        "мусорная строка\n"
        "2026-10-14 10:00:01 FAILED user=a ip=8.8.8.8\n"
        "ещё одна неправильная\n"
        "2026-13-99 99:99:99 FAILED user=b ip=not.an.ip\n"
        "2026-10-14 10:00:02 FAILED user=c ip=8.8.8.8\n",
        encoding="utf-8",
    )
    _, _, _, _, _, invalid = analyze_log(log, threshold=5, window_seconds=60)
    assert invalid == 3


def test_ipv6_supported(tmp_path):
    log = tmp_path / "ipv6.log"
    log.write_text(
        "2026-10-14 10:00:01 FAILED user=a ip=2001:db8::1\n"
        "2026-10-14 10:00:02 FAILED user=a ip=2001:db8::1\n",
        encoding="utf-8",
    )
    events, _, _, _, _, invalid = analyze_log(log, threshold=5, window_seconds=60)
    assert events == 2
    assert invalid == 0


# ============================================================
# ТЕСТЫ: Валидация параметров
# ============================================================
def test_invalid_threshold_raises(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        analyze_log(log, threshold=0, window_seconds=60)
    with pytest.raises(ValueError):
        analyze_log(log, threshold=-1, window_seconds=60)


def test_invalid_window_raises(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        analyze_log(log, threshold=5, window_seconds=0)
    with pytest.raises(ValueError):
        analyze_log(log, threshold=5, window_seconds=-1)
from detector import analyze_log


def test_detects_five_failed_attempts(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join([
            "2026-10-14 10:00:01 FAILED user=a ip=203.0.113.10",
            "2026-10-14 10:00:05 FAILED user=b ip=203.0.113.10",
            "2026-10-14 10:00:09 FAILED user=c ip=203.0.113.10",
            "2026-10-14 10:00:13 FAILED user=d ip=203.0.113.10",
            "2026-10-14 10:00:17 FAILED user=e ip=203.0.113.10",
        ]),
        encoding="utf-8"
    )

    total, suspicious, invalid = analyze_log(log_file)

    assert total == 5
    assert "203.0.113.10" in suspicious
    assert invalid == 0


def test_does_not_alert_when_attempts_are_too_far_apart(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join([
            "2026-10-14 10:00:01 FAILED user=a ip=203.0.113.10",
            "2026-10-14 10:00:05 FAILED user=b ip=203.0.113.10",
            "2026-10-14 10:05:01 FAILED user=c ip=203.0.113.10",
            "2026-10-14 10:05:05 FAILED user=d ip=203.0.113.10",
        ]),
        encoding="utf-8"
    )

    total, suspicious, invalid = analyze_log(log_file)

    assert total == 4
    assert suspicious == {}
    assert invalid == 0


def test_ignores_successful_logins(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join([
            "2026-10-14 10:00:01 SUCCESS user=a ip=203.0.113.10",
            "2026-10-14 10:00:05 SUCCESS user=b ip=203.0.113.10",
            "2026-10-14 10:00:09 SUCCESS user=c ip=203.0.113.10",
        ]),
        encoding="utf-8"
    )

    total, suspicious, invalid = analyze_log(log_file)

    assert total == 3
    assert suspicious == {}
    assert invalid == 0


def test_counts_invalid_log_lines(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "2025-03-10 12:00:00 FAILED user=alex ip=192.168.1.10\n"
        "this is not a valid log line\n"
        "2025-03-10 12:00:02 SUCCESS user=alex ip=192.168.1.10\n"
        "2025-99-99 12:00:00 FAILED user=bob ip=192.168.1.20\n",
        encoding="utf-8",
    )

    total_events, suspicious_ips, invalid_lines = analyze_log(
        log_file,
        threshold=5,
        window_seconds=60,
    )

    assert total_events == 2
    assert suspicious_ips == {}
    assert invalid_lines == 2


def test_detects_multiple_suspicious_ips(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "2025-03-10 12:00:00 FAILED user=alex ip=192.168.1.10\n"
        "2025-03-10 12:00:01 FAILED user=alex ip=192.168.1.10\n"
        "2025-03-10 12:00:02 FAILED user=alex ip=192.168.1.10\n"
        "2025-03-10 12:00:03 FAILED user=alex ip=192.168.1.10\n"
        "2025-03-10 12:00:04 FAILED user=alex ip=192.168.1.10\n"
        "2025-03-10 12:00:05 FAILED user=bob ip=192.168.1.20\n"
        "2025-03-10 12:00:06 FAILED user=bob ip=192.168.1.20\n"
        "2025-03-10 12:00:07 FAILED user=bob ip=192.168.1.20\n"
        "2025-03-10 12:00:08 FAILED user=bob ip=192.168.1.20\n"
        "2025-03-10 12:00:09 FAILED user=bob ip=192.168.1.20\n",
        encoding="utf-8",
    )

    total_events, suspicious_ips, invalid_lines = analyze_log(
        log_file,
        threshold=5,
        window_seconds=60,
    )

    assert total_events == 10
    assert invalid_lines == 0
    assert "192.168.1.10" in suspicious_ips
    assert "192.168.1.20" in suspicious_ips
    assert suspicious_ips["192.168.1.10"] == 5
    assert suspicious_ips["192.168.1.20"] == 5
