
import json
from pathlib import Path

from reporter import save_report


def test_report_is_created(tmp_path):
    output_path = tmp_path / "reports" / "test.json"

    save_report(
        output_path=output_path,
        total_events=10,
        suspicious_ips={"192.168.1.100": 5},
        invalid_lines=1,
        threshold=5,
        window_seconds=60,
    )

    assert output_path.exists()


def test_report_contains_correct_data(tmp_path):
    output_path = tmp_path / "report.json"

    save_report(
        output_path=output_path,
        total_events=10,
        suspicious_ips={"192.168.1.100": 5},
        invalid_lines=1,
        threshold=5,
        window_seconds=60,
    )

    with output_path.open("r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["summary"]["events_analyzed"] == 10
    assert report["summary"]["invalid_lines"] == 1
    assert report["summary"]["alerts_count"] == 1
    assert report["detection_settings"]["failed_attempts_threshold"] == 5
    assert report["detection_settings"]["time_window_seconds"] == 60


def test_report_without_alerts(tmp_path):
    output_path = tmp_path / "report.json"

    save_report(
        output_path=output_path,
        total_events=3,
        suspicious_ips={},
        invalid_lines=0,
        threshold=5,
        window_seconds=60,
    )

    with output_path.open("r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["alerts"] == []
    assert report["summary"]["alerts_count"] == 0
