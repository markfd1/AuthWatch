"""Геолокация IP через ip-api.com с локальным кэшем."""

import json
import ipaddress
import urllib.request
import urllib.error
from pathlib import Path


CACHE_FILE = Path(__file__).resolve().parent / "reports" / "geoip_cache.json"
API_URL = "http://ip-api.com/batch?fields=status,country,city,lat,lon,isp,query"


def _is_private(ip_str):
    """True для локальных/служебных адресов — их геолоцировать нельзя."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _load_cache():
    if not CACHE_FILE.exists():
        return {}
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache):
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(
            json.dumps(cache, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError:
        pass


def lookup_ips(ips):
    """
    Возвращает словарь {ip: info}.

    info:
        {
            "status": "ok" | "private" | "fail" | "error",
            "lat": float | None,
            "lon": float | None,
            "country": str,
            "city": str,
            "isp": str,
        }
    """
    cache = _load_cache()
    result = {}
    to_query = []

    for ip in ips:
        if ip in cache:
            result[ip] = cache[ip]
        elif _is_private(ip):
            result[ip] = {
                "status": "private",
                "lat": None, "lon": None,
                "country": "", "city": "", "isp": "",
            }
        else:
            to_query.append(ip)

    # ip-api.com позволяет до 100 адресов за один batch-запрос
    for i in range(0, len(to_query), 100):
        batch = to_query[i:i + 100]
        try:
            req = urllib.request.Request(
                API_URL,
                data=json.dumps(batch).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            for item in data:
                ip = item.get("query", "")
                if item.get("status") == "success":
                    info = {
                        "status": "ok",
                        "lat": item.get("lat"),
                        "lon": item.get("lon"),
                        "country": item.get("country", ""),
                        "city": item.get("city", ""),
                        "isp": item.get("isp", ""),
                    }
                else:
                    info = {
                        "status": "fail",
                        "lat": None, "lon": None,
                        "country": "", "city": "", "isp": "",
                    }
                result[ip] = info
                cache[ip] = info
            _save_cache(cache)

        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            for ip in batch:
                if ip not in result:
                    result[ip] = {
                        "status": "error",
                        "lat": None, "lon": None,
                        "country": "", "city": "", "isp": "",
                        "error": str(exc),
                    }

    return result