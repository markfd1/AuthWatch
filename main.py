from pathlib import Path

from detector import analyze_log

from reporter import save_report


LOG_FILE = Path(__file__).parent / "sample_logs" / "auth.log"

FAILED_ATTEMPTS_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60


def main():
    if not LOG_FILE.exists():
        print(f"Error: log file not found: {LOG_FILE}")
        return

    total_events, suspicious_ips, invalid_lines = analyze_log(
        LOG_FILE,
        threshold=FAILED_ATTEMPTS_THRESHOLD,
        window_seconds=TIME_WINDOW_SECONDS
    )

    print("=== AuthWatch Security Report ===")
    print(f"Events analyzed: {total_events}")
    print(f"Invalid lines: {invalid_lines}")
    print(f"Detection window: {TIME_WINDOW_SECONDS} seconds")
    print("\nSuspicious IP addresses:")

    if not suspicious_ips:
        print("No suspicious activity detected.")
    else:
        for ip, attempts in sorted(
                suspicious_ips.items(),
                key=lambda item: item[1],
                reverse=True
        ):
            print(
                f"[HIGH] {ip}: {attempts} failed login attempts "
                f"within {TIME_WINDOW_SECONDS} seconds"
            )

        print(
            f"[HIGH] {ip}: {attempts} failed login attempts "
            f"within {TIME_WINDOW_SECONDS} seconds"
        )


    report_path = Path(__file__).parent / "reports" / "latest_report.json"

    saved_path = save_report(
        output_path=report_path,
        total_events=total_events,
        suspicious_ips=suspicious_ips,
        invalid_lines=invalid_lines,
        threshold=FAILED_ATTEMPTS_THRESHOLD,
        window_seconds=TIME_WINDOW_SECONDS
    )

    print(f"\nJSON report saved to: {saved_path.resolve()}")

if __name__ == "__main__":
    main()


