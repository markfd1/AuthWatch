# 🔐 AuthWatch — Security Log Analyzer

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Platform: macOS / Linux / Windows](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](#-установка)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**AuthWatch** — локальный анализатор журналов аутентификации в стиле SIEM.
Обнаруживает brute-force, распределённые атаки (credential stuffing) и компрометацию
аккаунтов. Работает офлайн — логи не покидают вашу машину.

Разработан как pet-проект для портфолио в сфере информационной безопасности.
---

## ✨ Возможности

### Детекторы (по MITRE ATT&CK)

| Техника | ID | Описание |
|---|---|---|
| **Brute Force** | T1110.001 | N неудачных попыток с одного IP за скользящее окно M секунд |
| **Distributed / Password Spraying** | T1110.003 | Несколько IP атакуют один аккаунт за короткое время |
| **Valid Accounts (compromise)** | T1078 | Успешный вход после серии неудач — критичный сигнал |

### Интерфейс

- 📊 Дашборд с KPI-карточками и таблицами детекций
- 🗺 Интерактивная **карта атак** с геолокацией IP-адресов
- 📈 Графики (bar + donut) по подозрительным IP
- 📁 История анализов, экспорт в **JSON** и **CSV**

## 🖥 Требования

- **Python 3.10+**
- **Tkinter** (входит в стандартную поставку Python)
- Операционная система: macOS, Linux или Windows
- Интернет — только для подгрузки тайлов карты и геолокации IP (кэшируется локально)

> Проект разработан и протестирован на **macOS** (MacBook Air M-series, Python 3.11+).

---

## 🚀 Установка

### 1. Клонировать репозиторий

```bash
git clone https://github.com/ВАШ_ЮЗЕРНЕЙМ/AuthWatch.git
cd AuthWatch
