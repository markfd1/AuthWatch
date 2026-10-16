import json
import csv
import sys
import subprocess
from pathlib import Path
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from detector import analyze_log
from reporter import save_report
from csv_exporter import export_to_csv
from geoip import lookup_ips

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.font_manager as font_manager


# ============================================================
# ШРИФТ
# ============================================================
def get_ui_font():
    try:
        available = {f.name for f in font_manager.fontManager.ttflist}
    except Exception:
        available = set()
    if sys.platform == "win32":
        candidates = ["Segoe UI", "Calibri", "Arial"]
    elif sys.platform == "darwin":
        candidates = ["SF Pro Display", "SF Pro Text",
                      "Helvetica Neue", "Helvetica", "Arial"]
    else:
        candidates = ["Ubuntu", "Cantarell", "DejaVu Sans"]
    for name in candidates:
        if name in available:
            return name
    return "DejaVu Sans"


UI_FONT = get_ui_font()
print(f"[AuthWatch] Шрифт: {UI_FONT}")


# ============================================================
# ПАЛИТРА
# ============================================================
BG = "#0F172A"
PANEL = "#1E293B"
PANEL_LIGHT = "#334155"
BORDER = "#334155"
TEXT = "#F8FAFC"
MUTED = "#94A3B8"
ACCENT = "#3B82F6"
ACCENT_HOVER = "#2563EB"
GREEN = "#10B981"
RED = "#EF4444"
ORANGE = "#F59E0B"
YELLOW = "#FCD34D"
PINK = "#F472B6"

APPLE_BG = "#1C1C1E"
APPLE_CARD = "#2C2C2E"
APPLE_BORDER = "#3A3A3C"
APPLE_TEXT = "#FFFFFF"
APPLE_MUTED = "#8E8E93"
APPLE_BLUE = "#0A84FF"
APPLE_GREEN = "#30D158"
APPLE_ORANGE = "#FF9F0A"
APPLE_RED = "#FF453A"

PROJECT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = PROJECT_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# КНОПКА С HOVER-ЭФФЕКТОМ
# ============================================================
class ModernButton(tk.Frame):
    def __init__(self, parent, text, command,
                 bg=PANEL_LIGHT, fg=TEXT, hover_bg=BORDER,
                 padx=16, pady=9, font_size=10):
        super().__init__(parent, bg=bg, cursor="hand2")
        self.command = command
        self.default_bg = bg
        self.hover_bg = hover_bg

        self.label = tk.Label(
            self, text=text, bg=bg, fg=fg,
            font=(UI_FONT, font_size, "bold"),
            padx=padx, pady=pady,
        )
        self.label.pack(fill="both", expand=True)

        for w in (self, self.label):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", self._on_click)

    def _on_enter(self, _e=None):
        self.config(bg=self.hover_bg)
        self.label.config(bg=self.hover_bg)

    def _on_leave(self, _e=None):
        self.config(bg=self.default_bg)
        self.label.config(bg=self.default_bg)

    def _on_click(self, _e=None):
        self.command()


# ============================================================
# ПРИЛОЖЕНИЕ
# ============================================================
class AuthWatchApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AuthWatch — Анализатор событий безопасности")
        self.root.geometry("1280x900")
        self.root.minsize(1050, 750)
        self.root.configure(bg=BG)
        # Обычная стрелка по умолчанию; hand2 только на кнопках/кликабельном
        try:
            self.root.config(cursor="arrow")
        except tk.TclError:
            pass

        self.log_path = None
        self.last_results = None
        self.history_path = REPORTS_DIR / "history.json"

        self.threshold_var = tk.StringVar(value="5")
        self.window_var = tk.StringVar(value="60")
        self.status_var = tk.StringVar(value="Готов к работе")

        # Ссылки на текущий подраздел (History / Charts / Map)
        self.active_subview = None          # имя или None
        self.subview_frame = None           # Frame подраздела
        self.back_button = None             # кнопка «Назад» в шапке

        self.setup_styles()
        self.build_interface()

    # --------------------------------------------------------
    def setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background=PANEL, foreground=TEXT,
            fieldbackground=PANEL, rowheight=34,
            borderwidth=0, font=(UI_FONT, 10),
        )
        style.configure(
            "Treeview.Heading",
            background=PANEL, foreground=MUTED,
            font=(UI_FONT, 10, "bold"),
            relief="flat", padding=(10, 10),
        )
        style.map(
            "Treeview",
            background=[("selected", ACCENT)],
            foreground=[("selected", "#FFFFFF")],
        )
        style.layout("Treeview",
                     [("Treeview.treearea", {"sticky": "nswe"})])

        style.configure(
            "Vertical.TScrollbar",
            background=PANEL, troughcolor=BG, bordercolor=BG,
            arrowcolor=MUTED, relief="flat",
        )
        style.configure(
            "TSpinbox",
            fieldbackground=PANEL, foreground=TEXT,
            background=PANEL_LIGHT, arrowcolor=MUTED,
            bordercolor=BORDER,
        )

    # ========================================================
    # ОБЩАЯ РАЗМЕТКА: шапка + область контента
    # ========================================================
    def build_interface(self):
        # ===== ШАПКА (всегда видна) =====
        self.header = tk.Frame(self.root, bg=BG)
        self.header.pack(fill="x", padx=28, pady=(22, 14))

        # Кнопка «Назад» — создаётся, но пакуется только когда нужно
        self.back_button = ModernButton(
            self.header, "←  Назад", self.go_back,
            bg=PANEL, hover_bg=PANEL_LIGHT,
            padx=14, pady=6, font_size=10,
        )

        # Логотип
        self.logo_frame = tk.Frame(self.header, bg=BG)
        self.logo_frame.pack(side="left")

        tk.Label(self.logo_frame, text="◈", bg=BG, fg=ACCENT,
                 font=(UI_FONT, 26, "bold")).pack(side="left",
                                                   padx=(0, 10))
        tk.Label(self.logo_frame, text="AUTHWATCH", bg=BG, fg=TEXT,
                 font=(UI_FONT, 20, "bold")).pack(side="left")
        tk.Label(self.logo_frame, text="SECURITY LOG ANALYZER",
                 bg=BG, fg=MUTED,
                 font=(UI_FONT, 9, "bold")).pack(side="left",
                                                  padx=(14, 0),
                                                  pady=(6, 0))

        self.status_label = tk.Label(self.header, text="● READY",
                                     bg=BG, fg=GREEN,
                                     font=(UI_FONT, 10, "bold"))
        self.status_label.pack(side="right", pady=6)

        # ===== ОБЛАСТЬ КОНТЕНТА =====
        self.content = tk.Frame(self.root, bg=BG)
        self.content.pack(fill="both", expand=True)

        # Дашборд создаётся один раз и потом просто прячется/показывается
        self.dashboard_frame = tk.Frame(self.content, bg=BG)
        self.dashboard_frame.pack(fill="both", expand=True)
        self.build_dashboard(self.dashboard_frame)

        # Статус-бар внизу
        self.status_bar = tk.Frame(self.root, bg=BG)
        self.status_bar.pack(fill="x", padx=28, pady=(0, 14))
        tk.Label(self.status_bar, textvariable=self.status_var,
                 bg=BG, fg=MUTED, font=(UI_FONT, 9),
                 anchor="w").pack(side="left")
        tk.Label(self.status_bar,
                 text="AuthWatch  •  Локальный анализ журналов безопасности",
                 bg=BG, fg=MUTED, font=(UI_FONT, 9)).pack(side="right")

    # ========================================================
    # ДАШБОРД
    # ========================================================
    def build_dashboard(self, parent):
        # -------- Toolbar --------
        toolbar = tk.Frame(parent, bg=PANEL,
                           highlightbackground=BORDER,
                           highlightthickness=1)
        toolbar.pack(fill="x", pady=(0, 16))

        settings_row = tk.Frame(toolbar, bg=PANEL)
        settings_row.pack(fill="x", padx=18, pady=(14, 6))

        tk.Label(settings_row, text="Порог попыток:", bg=PANEL,
                 fg=MUTED, font=(UI_FONT, 10)).pack(side="left")
        ttk.Spinbox(settings_row, from_=1, to=1000, width=6,
                    textvariable=self.threshold_var).pack(
            side="left", padx=(8, 24))

        tk.Label(settings_row, text="Временное окно (сек.):", bg=PANEL,
                 fg=MUTED, font=(UI_FONT, 10)).pack(side="left")
        ttk.Spinbox(settings_row, from_=1, to=86400, width=8,
                    textvariable=self.window_var).pack(
            side="left", padx=(8, 0))

        tk.Frame(toolbar, bg=BORDER, height=1).pack(fill="x",
                                                    padx=18, pady=4)

        file_row = tk.Frame(toolbar, bg=PANEL)
        file_row.pack(fill="x", padx=18, pady=(8, 4))
        self.file_label = tk.Label(
            file_row, text="Файл журнала не выбран",
            bg=PANEL, fg=MUTED, font=(UI_FONT, 10), anchor="w",
        )
        self.file_label.pack(side="left", fill="x", expand=True)

        btn_row = tk.Frame(toolbar, bg=PANEL)
        btn_row.pack(fill="x", padx=18, pady=(8, 16))

        ModernButton(btn_row, "Выбрать лог", self.choose_file,
                     bg=PANEL_LIGHT, hover_bg=BORDER).pack(
            side="left", padx=(0, 8))
        ModernButton(btn_row, "▶  Запустить анализ", self.run_analysis,
                     bg=ACCENT, fg="#FFFFFF",
                     hover_bg=ACCENT_HOVER).pack(side="left", padx=(0, 8))
        ModernButton(btn_row, "Сохранить отчёт", self.save_current_report,
                     bg=PANEL_LIGHT, hover_bg=BORDER).pack(
            side="left", padx=(0, 8))
        ModernButton(btn_row, "Экспорт в CSV", self.export_csv,
                     bg=PANEL_LIGHT, hover_bg=BORDER).pack(
            side="left", padx=(0, 8))

        ModernButton(btn_row, "История", self.show_history,
                     bg=PANEL_LIGHT, hover_bg=BORDER).pack(
            side="right", padx=(0, 0))
        ModernButton(btn_row, "Карта атак", self.show_attack_map,
                     bg=PANEL_LIGHT, hover_bg=BORDER).pack(
            side="right", padx=(0, 8))
        ModernButton(btn_row, "Графики", self.show_charts,
                     bg=PANEL_LIGHT, hover_bg=BORDER).pack(
            side="right", padx=(0, 8))

        # -------- KPI Cards --------
        stats = tk.Frame(parent, bg=BG)
        stats.pack(fill="x", pady=(0, 16))

        self.events_value = self.make_stat_card(
            stats, "ОБРАБОТАНО СОБЫТИЙ", "0", ACCENT)
        self.suspicious_value = self.make_stat_card(
            stats, "ПОДОЗРИТЕЛЬНЫЕ IP", "0", ORANGE)
        self.distributed_value = self.make_stat_card(
            stats, "РАСПРЕДЕЛЁННЫЕ АТАКИ", "0", RED)
        self.compromise_value = self.make_stat_card(
            stats, "⚠ СКОМПРОМЕТИРОВАНО", "0", PINK)
        self.invalid_value = self.make_stat_card(
            stats, "НЕКОРРЕКТНЫЕ СТРОКИ", "0", YELLOW)

        # -------- Секция распределённых атак (скрыта) --------
        self.distributed_section = tk.Frame(parent, bg=BG)

        dist_header = tk.Frame(self.distributed_section, bg=BG)
        dist_header.pack(fill="x", pady=(0, 10))
        tk.Label(dist_header, text="⚠  РАСПРЕДЕЛЁННЫЕ АТАКИ",
                 bg=BG, fg=RED,
                 font=(UI_FONT, 12, "bold")).pack(side="left")
        tk.Label(dist_header,
                 text="несколько IP → один аккаунт в коротком окне",
                 bg=BG, fg=MUTED,
                 font=(UI_FONT, 9)).pack(side="left", padx=(12, 0))

        dist_table_frame = tk.Frame(
            self.distributed_section, bg=PANEL,
            highlightbackground=RED, highlightthickness=1,
        )
        dist_table_frame.pack(fill="x")

        dist_columns = ("user", "attempts", "ip_count", "ips",
                        "time_range")
        self.distributed_tree = ttk.Treeview(
            dist_table_frame, columns=dist_columns,
            show="headings", height=4,
        )
        dist_headings = {
            "user": "ПОЛЬЗОВАТЕЛЬ", "attempts": "ПОПЫТОК",
            "ip_count": "IP", "ips": "IP-АДРЕСА",
            "time_range": "ВРЕМЕННОЙ ДИАПАЗОН",
        }
        dist_widths = {"user": 140, "attempts": 90, "ip_count": 60,
                       "ips": 360, "time_range": 320}
        for col in dist_columns:
            self.distributed_tree.heading(col, text=dist_headings[col])
            self.distributed_tree.column(col, width=dist_widths[col],
                                         anchor="w" if col in ("user", "ips")
                                         else "center")
        self.distributed_tree.tag_configure("dist", foreground=RED)

        dist_scrollbar = ttk.Scrollbar(
            dist_table_frame, orient="vertical",
            command=self.distributed_tree.yview,
        )
        self.distributed_tree.configure(
            yscrollcommand=dist_scrollbar.set)
        self.distributed_tree.pack(side="left", fill="both",
                                   expand=True, padx=(12, 0), pady=10)
        dist_scrollbar.pack(side="right", fill="y",
                            pady=10, padx=(0, 12))

        # -------- Секция скомпрометированных (скрыта) --------
        self.compromise_section = tk.Frame(parent, bg=BG)

        comp_header = tk.Frame(self.compromise_section, bg=BG)
        comp_header.pack(fill="x", pady=(0, 10))
        tk.Label(comp_header,
                 text="⚠  СКОМПРОМЕТИРОВАННЫЕ АККАУНТЫ",
                 bg=BG, fg=PINK,
                 font=(UI_FONT, 12, "bold")).pack(side="left")
        tk.Label(comp_header,
                 text="успешный вход после серии неудачных попыток",
                 bg=BG, fg=MUTED,
                 font=(UI_FONT, 9)).pack(side="left", padx=(12, 0))

        comp_table_frame = tk.Frame(
            self.compromise_section, bg=PANEL,
            highlightbackground=PINK, highlightthickness=1,
        )
        comp_table_frame.pack(fill="x")

        comp_columns = ("user", "success_ip", "failed", "distinct",
                        "span", "time")
        self.compromise_tree = ttk.Treeview(
            comp_table_frame, columns=comp_columns,
            show="headings", height=4,
        )
        comp_headings = {
            "user": "ПОЛЬЗОВАТЕЛЬ", "success_ip": "IP УСПЕХА",
            "failed": "НЕУДАЧ", "distinct": "РАЗНЫХ IP",
            "span": "СПАН, С", "time": "ВРЕМЯ УСПЕХА",
        }
        comp_widths = {"user": 140, "success_ip": 180, "failed": 90,
                       "distinct": 100, "span": 90, "time": 220}
        for col in comp_columns:
            self.compromise_tree.heading(col, text=comp_headings[col])
            self.compromise_tree.column(
                col, width=comp_widths[col],
                anchor="w" if col in ("user", "success_ip") else "center",
            )
        self.compromise_tree.tag_configure("comp", foreground=PINK)

        comp_scrollbar = ttk.Scrollbar(
            comp_table_frame, orient="vertical",
            command=self.compromise_tree.yview,
        )
        self.compromise_tree.configure(
            yscrollcommand=comp_scrollbar.set)
        self.compromise_tree.pack(side="left", fill="both",
                                  expand=True, padx=(12, 0), pady=10)
        comp_scrollbar.pack(side="right", fill="y",
                            pady=10, padx=(0, 12))

        # -------- Основная таблица (по IP) --------
        self.section = tk.Frame(parent, bg=BG)
        self.section.pack(fill="both", expand=True, pady=(0, 14))

        tk.Label(self.section,
                 text="РЕЗУЛЬТАТЫ АНАЛИЗА (по IP)",
                 bg=BG, fg=TEXT,
                 font=(UI_FONT, 12, "bold")).pack(
            anchor="w", pady=(0, 10))

        table_frame = tk.Frame(self.section, bg=PANEL,
                               highlightbackground=BORDER,
                               highlightthickness=1)
        table_frame.pack(fill="both", expand=True)

        columns = ("ip", "attempts", "status")
        self.results_tree = ttk.Treeview(table_frame, columns=columns,
                                         show="headings")
        self.results_tree.heading("ip", text="IP-АДРЕС")
        self.results_tree.heading(
            "attempts", text="МАКС. НЕУДАЧНЫХ ПОПЫТОК В ОКНЕ")
        self.results_tree.heading("status", text="СТАТУС")

        self.results_tree.column("ip", width=240, anchor="w")
        self.results_tree.column("attempts", width=340, anchor="center")
        self.results_tree.column("status", width=200, anchor="center")

        self.results_tree.tag_configure("even", background=PANEL)
        self.results_tree.tag_configure("odd", background="#162032")
        self.results_tree.tag_configure("empty", foreground=MUTED)
        self.results_tree.tag_configure("danger", foreground=RED)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical",
                                  command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        self.results_tree.pack(side="left", fill="both",
                               expand=True, padx=(12, 0), pady=12)
        scrollbar.pack(side="right", fill="y",
                       pady=12, padx=(0, 12))

    # --------------------------------------------------------
    def make_stat_card(self, parent, title, value, color):
        card = tk.Frame(parent, bg=PANEL,
                        highlightbackground=BORDER,
                        highlightthickness=1)
        card.pack(side="left", fill="both", expand=True, padx=(0, 12))
        tk.Frame(card, bg=color, height=4).pack(fill="x")
        content = tk.Frame(card, bg=PANEL, padx=16, pady=14)
        content.pack(fill="both", expand=True)
        tk.Label(content, text=title, bg=PANEL, fg=MUTED,
                 font=(UI_FONT, 8, "bold")).pack(anchor="w")
        lbl = tk.Label(content, text=value, bg=PANEL, fg=TEXT,
                       font=(UI_FONT, 24, "bold"))
        lbl.pack(anchor="w", pady=(6, 0))
        return lbl

    # ========================================================
    # ПЕРЕКЛЮЧЕНИЕ МЕЖДУ ДАШБОРДОМ И ПОДРАЗДЕЛАМИ
    # ========================================================
    def _open_subview(self, name, builder):
        """Открывает подраздел (history/charts/map) вместо дашборда."""
        # Закрыть предыдущий подраздел, если был
        if self.subview_frame is not None:
            self.subview_frame.destroy()
            self.subview_frame = None

        self.dashboard_frame.pack_forget()

        self.subview_frame = tk.Frame(self.content, bg=BG)
        self.subview_frame.pack(fill="both", expand=True)

        self.active_subview = name
        builder(self.subview_frame)

        # Показать кнопку «Назад» слева от логотипа
        if not self.back_button.winfo_ismapped():
            self.back_button.pack(side="left", padx=(0, 16),
                                  before=self.logo_frame)

    def go_back(self):
        """Возврат на дашборд."""
        if self.subview_frame is not None:
            self.subview_frame.destroy()
            self.subview_frame = None
        self.active_subview = None

        if self.back_button.winfo_ismapped():
            self.back_button.pack_forget()

        self.dashboard_frame.pack(fill="both", expand=True)
        self.status_var.set("Готов к работе")

    # ========================================================
    # ДЕЙСТВИЯ
    # ========================================================
    def choose_file(self):
        file_path = filedialog.askopenfilename(
            title="Выберите файл журнала",
            initialdir=str(PROJECT_DIR),
            filetypes=[("Файлы журналов", "*.log *.txt"),
                       ("Все файлы", "*.*")],
            parent=self.root,
        )
        if not file_path:
            return
        self.log_path = Path(file_path)
        self.file_label.config(text=f"📄 {self.log_path.name}", fg=TEXT)
        self.status_label.config(text="● ФАЙЛ ВЫБРАН", fg=ACCENT)
        self.status_var.set("Файл выбран. Можно запускать анализ.")

    def run_analysis(self):
        if not self.log_path:
            messagebox.showwarning("Файл не выбран",
                                   "Сначала выбери файл журнала.",
                                   parent=self.root)
            return
        try:
            threshold = int(self.threshold_var.get())
            window_seconds = int(self.window_var.get())
            if not 1 <= threshold <= 1000:
                raise ValueError
            if not 1 <= window_seconds <= 86400:
                raise ValueError
        except (ValueError, tk.TclError):
            messagebox.showerror("Некорректные настройки",
                                 "Порог: 1–1000, окно: 1–86400 сек.",
                                 parent=self.root)
            return

        if not self.log_path.is_file():
            messagebox.showerror("Ошибка",
                                 "Выбранный файл не существует.",
                                 parent=self.root)
            return

        try:
            self.status_var.set("Выполняется анализ...")
            self.root.update_idletasks()

            (total_events,
             attempts_by_ip,
             suspicious_ips,
             distributed_attacks,
             compromises,
             invalid_lines) = analyze_log(
                self.log_path,
                threshold=threshold,
                window_seconds=window_seconds,
            )

            self.last_results = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "file": str(self.log_path),
                "events": total_events,
                "attempts_by_ip": attempts_by_ip,
                "suspicious_ips": suspicious_ips,
                "distributed_attacks": distributed_attacks,
                "compromises": compromises,
                "invalid_lines": invalid_lines,
                "threshold": threshold,
                "window_seconds": window_seconds,
            }
            self.update_results()
            self.status_label.config(text="● АНАЛИЗ ЗАВЕРШЁН", fg=GREEN)
            self.status_var.set("Анализ завершён успешно.")
        except Exception as error:
            self.status_label.config(text="● ОШИБКА", fg=RED)
            self.status_var.set("Ошибка анализа.")
            messagebox.showerror("Ошибка анализа",
                                 f"Не удалось проанализировать журнал:\n{error}",
                                 parent=self.root)

    def update_results(self):
        if not self.last_results:
            return

        result = self.last_results
        attempts_by_ip = result.get("attempts_by_ip", {})
        suspicious_ips = result["suspicious_ips"]
        distributed = result.get("distributed_attacks", {})
        compromises = result.get("compromises", [])
        threshold = result["threshold"]

        self.events_value.config(text=str(result["events"]))
        self.suspicious_value.config(text=str(len(suspicious_ips)))
        self.distributed_value.config(text=str(len(distributed)))
        self.compromise_value.config(text=str(len(compromises)))
        self.invalid_value.config(text=str(result["invalid_lines"]))

        # ---- Основная таблица ----
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        if not attempts_by_ip:
            self.results_tree.insert(
                "", "end",
                values=("—", "—", "Неудачных попыток не обнаружено"),
                tags=("empty",),
            )
        else:
            for i, (ip, attempts) in enumerate(sorted(
                attempts_by_ip.items(),
                key=lambda x: x[1], reverse=True
            )):
                base_tag = "odd" if i % 2 else "even"
                if ip in suspicious_ips:
                    status = "⚠  Подозрительная активность"
                    tag = f"{base_tag} danger"
                else:
                    status = f"Норма (< {threshold})"
                    tag = base_tag
                self.results_tree.insert(
                    "", "end",
                    values=(ip, attempts, status),
                    tags=(tag,),
                )

        # ---- Распределённые атаки ----
        for item in self.distributed_tree.get_children():
            self.distributed_tree.delete(item)

        if distributed:
            if not self.distributed_section.winfo_ismapped():
                self.distributed_section.pack(
                    fill="x", pady=(0, 14), before=self.section)
            for user, info in sorted(
                distributed.items(),
                key=lambda x: x[1]["attempts"], reverse=True,
            ):
                self.distributed_tree.insert(
                    "", "end",
                    values=(
                        user, info["attempts"], info["ip_count"],
                        ", ".join(info["ips"]),
                        f'{info["first_seen"]}  →  {info["last_seen"]}',
                    ),
                    tags=("dist",),
                )
        else:
            if self.distributed_section.winfo_ismapped():
                self.distributed_section.pack_forget()

        # ---- Скомпрометированные ----
        for item in self.compromise_tree.get_children():
            self.compromise_tree.delete(item)

        if compromises:
            if not self.compromise_section.winfo_ismapped():
                self.compromise_section.pack(
                    fill="x", pady=(0, 14), before=self.section)
            for c in sorted(compromises,
                            key=lambda x: x["failed_attempts"],
                            reverse=True):
                self.compromise_tree.insert(
                    "", "end",
                    values=(
                        c["user"], c["success_ip"],
                        c["failed_attempts"], c["distinct_ips"],
                        c["span_seconds"], c["success_time"],
                    ),
                    tags=("comp",),
                )
        else:
            if self.compromise_section.winfo_ismapped():
                self.compromise_section.pack_forget()

    def save_current_report(self):
        if not self.last_results:
            messagebox.showwarning("Нет результатов",
                                   "Сначала выполни анализ журнала.",
                                   parent=self.root)
            return
        result = self.last_results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = REPORTS_DIR / f"report_{timestamp}.txt"

        try:
            save_report(
                output_path=report_path,
                total_events=result["events"],
                suspicious_ips=result["suspicious_ips"],
                invalid_lines=result["invalid_lines"],
                threshold=result["threshold"],
                window_seconds=result["window_seconds"],
                attempts_by_ip=result.get("attempts_by_ip"),
                distributed_attacks=result.get("distributed_attacks"),
                compromises=result.get("compromises"),
            )
            history = self.load_history()
            history.append({
                "timestamp": result["timestamp"],
                "source_file": result["file"],
                "report_file": str(report_path),
                "events": result["events"],
                "suspicious_ips": len(result["suspicious_ips"]),
                "distributed_attacks":
                    len(result.get("distributed_attacks", {})),
                "compromises":
                    len(result.get("compromises", [])),
                "invalid_lines": result["invalid_lines"],
                "threshold": result["threshold"],
                "window_seconds": result["window_seconds"],
            })
            with self.history_path.open("w", encoding="utf-8") as f:
                json.dump(history, f, ensure_ascii=False, indent=4)
            self.status_var.set(f"Отчёт сохранён: {report_path.name}")
            messagebox.showinfo("Отчёт сохранён",
                                f"Отчёт успешно сохранён:\n{report_path}",
                                parent=self.root)
        except Exception as error:
            messagebox.showerror("Ошибка сохранения",
                                 f"Не удалось сохранить отчёт:\n{error}",
                                 parent=self.root)

    def export_csv(self):
        if not self.last_results:
            messagebox.showwarning("Нет результатов",
                                   "Сначала выполни анализ журнала.",
                                   parent=self.root)
            return
        default_name = ("authwatch_"
                        + datetime.now().strftime("%Y%m%d_%H%M%S")
                        + ".csv")
        file_path = filedialog.asksaveasfilename(
            title="Экспорт результатов в CSV",
            defaultextension=".csv",
            initialdir=str(REPORTS_DIR),
            initialfile=default_name,
            filetypes=[("CSV-файлы", "*.csv")],
            parent=self.root,
        )
        if not file_path:
            return
        try:
            saved_path = export_to_csv(file_path, self.last_results)
            self.status_var.set(f"CSV сохранён: {Path(saved_path).name}")
            messagebox.showinfo("Экспорт завершён",
                                f"Результаты сохранены:\n{saved_path}",
                                parent=self.root)
        except (OSError, csv.Error, ValueError) as error:
            messagebox.showerror("Ошибка экспорта",
                                 f"Не удалось экспортировать:\n{error}",
                                 parent=self.root)

    def load_history(self):
        if not self.history_path.exists():
            return []
        try:
            with self.history_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    # ========================================================
    # ПОДРАЗДЕЛ: ИСТОРИЯ
    # ========================================================
    def show_history(self):
        self._open_subview("history", self._build_history_view)

    def _build_history_view(self, parent):
        history = self.load_history()

        header = tk.Frame(parent, bg=BG)
        header.pack(fill="x", pady=(0, 14))
        tk.Label(header, text="ИСТОРИЯ АНАЛИЗОВ", bg=BG, fg=TEXT,
                 font=(UI_FONT, 16, "bold")).pack(side="left")
        tk.Label(header, text=f"Всего запусков: {len(history)}",
                 bg=BG, fg=MUTED,
                 font=(UI_FONT, 10)).pack(side="left", padx=(14, 0),
                                           pady=(4, 0))

        if not history:
            empty = tk.Frame(parent, bg=PANEL,
                             highlightbackground=BORDER,
                             highlightthickness=1)
            empty.pack(fill="both", expand=True)
            tk.Label(empty, text="История пока пуста",
                     bg=PANEL, fg=MUTED,
                     font=(UI_FONT, 12)).pack(expand=True)
            return

        table_frame = tk.Frame(parent, bg=PANEL,
                               highlightbackground=BORDER,
                               highlightthickness=1)
        table_frame.pack(fill="both", expand=True)

        columns = ("timestamp", "source_file", "events",
                   "suspicious_ips", "distributed", "compromises",
                   "invalid_lines", "threshold", "window_seconds")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        headings = {
            "timestamp": "ДАТА И ВРЕМЯ",
            "source_file": "ИСХОДНЫЙ ФАЙЛ",
            "events": "СОБЫТИЯ",
            "suspicious_ips": "ПОДОЗР. IP",
            "distributed": "РАСПР. АТАКИ",
            "compromises": "СКОМПР.",
            "invalid_lines": "ОШИБКИ",
            "threshold": "ПОРОГ",
            "window_seconds": "ОКНО (С)",
        }
        widths = {
            "timestamp": 160, "source_file": 220, "events": 70,
            "suspicious_ips": 90, "distributed": 100,
            "compromises": 80, "invalid_lines": 70,
            "threshold": 70, "window_seconds": 80,
        }
        for col in columns:
            tree.heading(col, text=headings[col])
            tree.column(col, width=widths[col], minwidth=60,
                        anchor="w" if col in ("timestamp", "source_file")
                        else "center")

        tree.tag_configure("even", background=PANEL)
        tree.tag_configure("odd", background="#162032")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical",
                                  command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True,
                  padx=(12, 0), pady=12)
        scrollbar.pack(side="right", fill="y", pady=12, padx=(0, 12))

        for i, entry in enumerate(reversed(history)):
            tag = "odd" if i % 2 else "even"
            tree.insert(
                "", "end",
                values=(
                    entry.get("timestamp", "—"),
                    Path(entry.get("source_file", "—")).name,
                    entry.get("events", 0),
                    entry.get("suspicious_ips", 0),
                    entry.get("distributed_attacks", 0),
                    entry.get("compromises", 0),
                    entry.get("invalid_lines", 0),
                    entry.get("threshold", "—"),
                    entry.get("window_seconds", "—"),
                ),
                tags=(tag,),
            )

        def open_selected_report():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Отчёт не выбран",
                                       "Выбери запись в истории.",
                                       parent=self.root)
                return
            values = tree.item(selected[0], "values")
            selected_ts, selected_src = values[0], values[1]
            report_path = None
            for entry in history:
                if (entry.get("timestamp") == selected_ts
                        and Path(entry.get("source_file", "")).name
                        == selected_src):
                    report_path = entry.get("report_file")
                    break
            if not report_path:
                messagebox.showwarning("Отчёт не найден",
                                       "Путь к отчёту отсутствует.",
                                       parent=self.root)
                return
            path = Path(report_path)
            if not path.is_file():
                messagebox.showerror("Файл не найден",
                                     f"Файл не найден:\n{path}",
                                     parent=self.root)
                return
            try:
                if sys.platform == "darwin":
                    subprocess.Popen(["open", str(path)])
                elif sys.platform.startswith("win"):
                    import os
                    os.startfile(str(path))
                else:
                    subprocess.Popen(["xdg-open", str(path)])
            except Exception as error:
                messagebox.showerror("Ошибка",
                                     f"Не открыть отчёт:\n{error}",
                                     parent=self.root)

        tree.bind("<Double-1>", lambda _e: open_selected_report())

        btns = tk.Frame(parent, bg=BG)
        btns.pack(fill="x", pady=(12, 0))
        ModernButton(btns, "Открыть выбранный отчёт",
                     open_selected_report,
                     bg=ACCENT, fg="#FFFFFF",
                     hover_bg=ACCENT_HOVER).pack(side="right")
        tk.Label(btns, text="Двойной клик по строке — открыть отчёт",
                 bg=BG, fg=MUTED,
                 font=(UI_FONT, 9)).pack(side="left", pady=10)

    # ========================================================
    # ПОДРАЗДЕЛ: ГРАФИКИ
    # ========================================================
    def show_charts(self):
        if not self.last_results:
            messagebox.showwarning("Нет данных",
                                   "Сначала выполни анализ журнала.",
                                   parent=self.root)
            return
        self._open_subview("charts", self._build_charts_view)

    def _build_charts_view(self, parent):
        result = self.last_results
        suspicious_ips = result["suspicious_ips"]

        header = tk.Frame(parent, bg=BG)
        header.pack(fill="x", pady=(0, 14))
        tk.Label(header, text="АНАЛИТИКА БЕЗОПАСНОСТИ", bg=BG, fg=TEXT,
                 font=(UI_FONT, 16, "bold")).pack(anchor="w")
        tk.Label(header, text=f"Источник: {Path(result['file']).name}",
                 bg=BG, fg=MUTED,
                 font=(UI_FONT, 10)).pack(anchor="w", pady=(2, 0))

        chart_container = tk.Frame(parent, bg=APPLE_CARD,
                                   highlightbackground=APPLE_BORDER,
                                   highlightthickness=1)
        chart_container.pack(fill="both", expand=True)

        figure = Figure(figsize=(10, 5.5), dpi=100,
                        facecolor=APPLE_CARD, constrained_layout=True)
        bar_ax = figure.add_subplot(121)
        pie_ax = figure.add_subplot(122)

        for ax in (bar_ax, pie_ax):
            ax.set_facecolor(APPLE_CARD)
            ax.tick_params(colors=APPLE_MUTED, labelsize=9)
            for spine in ax.spines.values():
                spine.set_visible(False)

        sorted_ips = sorted(suspicious_ips.items(),
                            key=lambda item: item[1],
                            reverse=True)[:10]

        if sorted_ips:
            ips = [item[0] for item in sorted_ips]
            attempts = [item[1] for item in sorted_ips]
            bars = bar_ax.barh(ips[::-1], attempts[::-1],
                               color=APPLE_BLUE, height=0.5, alpha=0.9)
            bar_ax.set_title("Подозрительные IP", color=APPLE_TEXT,
                             fontsize=13, pad=20,
                             fontfamily=UI_FONT, fontweight="bold")
            bar_ax.set_xlabel("Неудачные попытки", color=APPLE_MUTED,
                              fontsize=10, labelpad=10,
                              fontfamily=UI_FONT)
            bar_ax.grid(axis="x", color=APPLE_BORDER,
                        linestyle="-", linewidth=0.5, alpha=0.5)
            bar_ax.set_axisbelow(True)
            bar_ax.set_xlim(0, max(attempts) * 1.2)
            for bar in bars:
                w = bar.get_width()
                bar_ax.text(w + 0.3,
                            bar.get_y() + bar.get_height() / 2,
                            f"{int(w)}", ha="left", va="center",
                            color=APPLE_TEXT, fontsize=9,
                            fontweight="bold", fontfamily=UI_FONT)
        else:
            bar_ax.text(0.5, 0.5, "Нет подозрительных IP",
                        ha="center", va="center",
                        color=APPLE_MUTED, fontsize=13,
                        transform=bar_ax.transAxes, fontfamily=UI_FONT)
            bar_ax.set_xticks([]); bar_ax.set_yticks([])
            bar_ax.set_title("Подозрительные IP", color=APPLE_TEXT,
                             fontsize=13, pad=20,
                             fontfamily=UI_FONT, fontweight="bold")

        valid = result["events"]
        invalid = result["invalid_lines"]
        pie_ax.set_title("Результат обработки", color=APPLE_TEXT,
                         fontsize=13, pad=20,
                         fontfamily=UI_FONT, fontweight="bold")

        if valid + invalid > 0:
            values = [valid, invalid]
            labels = [f"Корректные: {valid}", f"Ошибки: {invalid}"]
            colors = [APPLE_GREEN, APPLE_ORANGE]
            filtered = [(v, l, c)
                        for v, l, c in zip(values, labels, colors) if v > 0]
            if filtered:
                vals, lbls, clrs = zip(*filtered)
                wedges, texts, autotexts = pie_ax.pie(
                    vals, labels=lbls, colors=clrs,
                    autopct="%1.1f%%", startangle=90,
                    wedgeprops=dict(width=0.4, edgecolor=APPLE_CARD,
                                    linewidth=4),
                    textprops=dict(color=APPLE_TEXT, fontsize=10,
                                   fontfamily=UI_FONT),
                )
                for at in autotexts:
                    at.set_color(APPLE_BG)
                    at.set_fontweight("bold")
                    at.set_fontfamily(UI_FONT)
                total = sum(vals)
                pie_ax.text(0, 0, f"{total}\nСобытий",
                            ha="center", va="center",
                            color=APPLE_TEXT, fontsize=16,
                            fontweight="bold", fontfamily=UI_FONT)
        else:
            pie_ax.text(0.5, 0.5, "Нет данных",
                        ha="center", va="center",
                        color=APPLE_MUTED, fontsize=13,
                        transform=pie_ax.transAxes,
                        fontfamily=UI_FONT)
            pie_ax.set_xticks([]); pie_ax.set_yticks([])

        canvas = FigureCanvasTkAgg(figure, master=chart_container)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True,
                                    padx=20, pady=20)
        canvas.get_tk_widget().config(cursor="crosshair")

    # ========================================================
    # ПОДРАЗДЕЛ: КАРТА АТАК
    # ========================================================
    def show_attack_map(self):
        if not self.last_results:
            messagebox.showwarning("Нет данных",
                                   "Сначала выполни анализ журнала.",
                                   parent=self.root)
            return
        # Проверим зависимости заранее
        suspicious_ips = self.last_results.get("suspicious_ips", {})
        distributed = self.last_results.get("distributed_attacks", {})
        if not suspicious_ips and not distributed:
            messagebox.showinfo("Карта атак",
                                "Нет подозрительных IP для отображения.",
                                parent=self.root)
            return
        try:
            import tkintermapview  # noqa: F401
        except ImportError:
            messagebox.showerror(
                "Библиотека не установлена",
                "Для карты атак установите:\n\n"
                "    pip install tkintermapview\n\n"
                "Затем перезапустите приложение.",
                parent=self.root,
            )
            return
        self._open_subview("map", self._build_map_view)

    def _build_map_view(self, parent):
        import tkintermapview

        result = self.last_results
        suspicious_ips = result.get("suspicious_ips", {})
        distributed = result.get("distributed_attacks", {})

        ips_info = {}
        for ip, attempts in suspicious_ips.items():
            ips_info[ip] = {"attempts": attempts, "in_distributed": []}
        for user, info in distributed.items():
            for ip in info.get("ips", []):
                if ip not in ips_info:
                    ips_info[ip] = {"attempts": 0,
                                    "in_distributed": [user]}
                else:
                    ips_info[ip]["in_distributed"].append(user)

        self.status_var.set("Определение геолокации IP-адресов...")
        self.root.update_idletasks()
        try:
            geo = lookup_ips(list(ips_info.keys()))
        except Exception as error:
            self.status_var.set("Ошибка геолокации.")
            messagebox.showerror("Ошибка геолокации",
                                 f"Не удалось определить координаты:\n{error}",
                                 parent=self.root)
            return

        plottable = []
        failed_geo = []
        for ip, info in ips_info.items():
            g = geo.get(ip, {})
            if g.get("status") == "ok" and g.get("lat") is not None:
                plottable.append((ip, info, g))
            else:
                failed_geo.append(ip)

        if not plottable:
            details = []
            for ip in failed_geo:
                st = geo.get(ip, {}).get("status", "unknown")
                if st == "private":
                    r = "приватный/служебный диапазон"
                elif st == "fail":
                    r = "не маршрутизируется (TEST-NET / reserved)"
                elif st == "error":
                    r = "ошибка сети: " + geo.get(ip, {}).get("error", "")[:60]
                else:
                    r = st
                details.append(f"  • {ip} — {r}")
            messagebox.showinfo(
                "Карта атак",
                "Не удалось определить координаты ни одного IP.\n\n"
                f"Детали по {len(failed_geo)} адресам:\n"
                + "\n".join(details[:15])
                + (f"\n  … и ещё {len(failed_geo) - 15}"
                   if len(failed_geo) > 15 else ""),
                parent=self.root,
            )
            self.status_var.set("Готово.")
            return

        # ---- Заголовок подраздела ----
        header = tk.Frame(parent, bg=BG)
        header.pack(fill="x", pady=(0, 12))
        tk.Label(header, text="КАРТА АТАК", bg=BG, fg=TEXT,
                 font=(UI_FONT, 16, "bold")).pack(anchor="w")
        tk.Label(header,
                 text=(f"Источник: {Path(result['file']).name}   •   "
                       f"точек: {len(plottable)}   •   "
                       f"не определено: {len(failed_geo)}"),
                 bg=BG, fg=MUTED,
                 font=(UI_FONT, 10)).pack(anchor="w", pady=(2, 0))

        main_frame = tk.Frame(parent, bg=BG)
        main_frame.pack(fill="both", expand=True)

        # ---- Sidebar ----
        sidebar = tk.Frame(main_frame, bg=PANEL,
                           highlightbackground=BORDER,
                           highlightthickness=1, width=290)
        sidebar.pack(side="right", fill="y", padx=(12, 0))
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="ЛЕГЕНДА", bg=PANEL, fg=MUTED,
                 font=(UI_FONT, 9, "bold")).pack(anchor="w",
                                                  padx=16, pady=(16, 8))
        legend = tk.Frame(sidebar, bg=PANEL)
        legend.pack(fill="x", padx=16, pady=(0, 10))
        for color, label in [
            (RED, "Подозрительный IP"),
            (ORANGE, "Участник распр. атаки"),
        ]:
            row = tk.Frame(legend, bg=PANEL)
            row.pack(fill="x", pady=2)
            tk.Label(row, text="●", bg=PANEL, fg=color,
                     font=(UI_FONT, 12)).pack(side="left")
            tk.Label(row, text=label, bg=PANEL, fg=TEXT,
                     font=(UI_FONT, 9)).pack(side="left", padx=(6, 0))

        tk.Frame(sidebar, bg=BORDER, height=1).pack(
            fill="x", padx=16, pady=(4, 12))
        tk.Label(sidebar, text="СПИСОК IP", bg=PANEL, fg=MUTED,
                 font=(UI_FONT, 9, "bold")).pack(anchor="w",
                                                  padx=16, pady=(0, 8))

        list_container = tk.Frame(sidebar, bg=PANEL)
        list_container.pack(fill="both", expand=True, padx=8,
                            pady=(0, 12))
        list_canvas = tk.Canvas(list_container, bg=PANEL,
                                highlightthickness=0, bd=0)
        list_scrollbar = ttk.Scrollbar(list_container, orient="vertical",
                                       command=list_canvas.yview)
        list_inner = tk.Frame(list_canvas, bg=PANEL)
        list_inner.bind(
            "<Configure>",
            lambda _e: list_canvas.configure(
                scrollregion=list_canvas.bbox("all")),
        )
        list_canvas.create_window((0, 0), window=list_inner, anchor="nw")
        list_canvas.configure(yscrollcommand=list_scrollbar.set)
        list_canvas.pack(side="left", fill="both", expand=True)
        list_scrollbar.pack(side="right", fill="y")

        # ---- Map ----
        map_frame = tk.Frame(main_frame, bg=BG,
                             highlightbackground=BORDER,
                             highlightthickness=1)
        map_frame.pack(side="left", fill="both", expand=True)

        map_widget = tkintermapview.TkinterMapView(
            map_frame, corner_radius=0, bg_color=PANEL,
        )
        map_widget.pack(fill="both", expand=True, padx=1, pady=1)
        map_widget.set_tile_server(
            "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
            max_zoom=19,
        )

        # ---- Popup-окно по клику на маркер (обычный Toplevel) ----
        def make_popup(ip, info, g):
            def _open():
                w = tk.Toplevel(self.root)
                w.title(f"IP: {ip}")
                w.geometry("440x340")
                w.configure(bg=PANEL)

                tk.Label(w, text=f"  {ip}", bg=PANEL, fg=TEXT,
                         font=(UI_FONT, 14, "bold")).pack(
                    anchor="w", padx=20, pady=(20, 8))
                tk.Frame(w, bg=BORDER, height=1).pack(fill="x", padx=20)

                lat_v, lon_v = g.get("lat"), g.get("lon")
                coords = (f"{lat_v:.4f}, {lon_v:.4f}"
                          if lat_v is not None and lon_v is not None
                          else "—")
                details = [
                    ("Город", g.get("city") or "—"),
                    ("Страна", g.get("country") or "—"),
                    ("Провайдер", g.get("isp") or "—"),
                    ("Координаты", coords),
                    ("Макс. попыток", info.get("attempts", 0)),
                    ("Распр. атака",
                     ", ".join(info.get("in_distributed", [])) or "нет"),
                ]
                for label, value in details:
                    row = tk.Frame(w, bg=PANEL)
                    row.pack(fill="x", padx=20, pady=3)
                    tk.Label(row, text=f"{label}:", bg=PANEL, fg=MUTED,
                             font=(UI_FONT, 10), width=15,
                             anchor="w").pack(side="left")
                    tk.Label(row, text=str(value), bg=PANEL, fg=TEXT,
                             font=(UI_FONT, 10),
                             anchor="w").pack(side="left")
                ModernButton(w, "Закрыть", w.destroy,
                             bg=ACCENT, fg="#FFFFFF",
                             hover_bg=ACCENT_HOVER).pack(pady=16)
            return _open

        for ip, info, g in plottable:
            in_susp = info.get("attempts", 0) > 0
            in_dist = bool(info.get("in_distributed"))
            color = RED if in_susp else (ORANGE if in_dist else MUTED)
            popup = make_popup(ip, info, g)
            map_widget.set_marker(
                g["lat"], g["lon"],
                text=ip,
                text_color="#FFFFFF",
                marker_color_circle=color,
                marker_color_outside=BG,
                command=lambda _m, p=popup: p(),
            )

        lats = [g["lat"] for _, _, g in plottable]
        lons = [g["lon"] for _, _, g in plottable]
        if len(plottable) == 1:
            map_widget.set_position(lats[0], lons[0])
            map_widget.set_zoom(6)
        else:
            map_widget.fit_bounding_box(
                (max(lats) + 5, min(lons) - 5),
                (min(lats) - 5, max(lons) + 5),
            )

        # ---- Список IP в сайдбаре ----
        def bind_recursive(widget, callback):
            widget.bind("<Button-1>", callback)
            for child in widget.winfo_children():
                bind_recursive(child, callback)

        sorted_ips = sorted(
            plottable,
            key=lambda x: (x[1]["attempts"],
                           len(x[1]["in_distributed"])),
            reverse=True,
        )
        for ip, info, g in sorted_ips:
            row = tk.Frame(list_inner, bg=PANEL_LIGHT, cursor="hand2")
            row.pack(fill="x", padx=6, pady=3)

            in_susp = info["attempts"] > 0
            in_dist = bool(info.get("in_distributed"))
            dot_color = RED if in_susp else (ORANGE if in_dist else MUTED)

            tk.Label(row, text="●", bg=PANEL_LIGHT, fg=dot_color,
                     font=(UI_FONT, 12)).pack(side="left",
                                              padx=(10, 6), pady=8)
            text_frame = tk.Frame(row, bg=PANEL_LIGHT)
            text_frame.pack(side="left", fill="x", expand=True,
                            pady=6, padx=(0, 8))
            tk.Label(text_frame, text=ip, bg=PANEL_LIGHT, fg=TEXT,
                     font=(UI_FONT, 10, "bold"),
                     anchor="w").pack(fill="x")
            subtitle = g.get("city") or g.get("country") or "—"
            if info["attempts"]:
                subtitle += f"   •   {info['attempts']} поп."
            tk.Label(text_frame, text=subtitle, bg=PANEL_LIGHT,
                     fg=MUTED, font=(UI_FONT, 8),
                     anchor="w").pack(fill="x")

            def _focus(lat=g["lat"], lon=g["lon"]):
                map_widget.set_position(lat, lon)
                map_widget.set_zoom(8)
            bind_recursive(row, lambda _e, f=_focus: f())

        self.status_var.set(
            f"Карта атак: {len(plottable)} точек  •  "
            f"не определено: {len(failed_geo)}"
        )


# ============================================================
def main():
    root = tk.Tk()
    try:
        from tkinter import font as tkfont
        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(family=UI_FONT, size=10)
    except Exception:
        pass
    AuthWatchApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()