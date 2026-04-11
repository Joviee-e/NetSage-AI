"""Telegram notification helper for threshold-based realtime alerts."""

from __future__ import annotations

import os
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(dotenv_path=ROOT_ENV_PATH)


def send_telegram_alert(message: str) -> None:
    """Send a Telegram message if bot credentials are configured.

    Fails silently by design to avoid breaking the realtime pipeline when
    Telegram is not configured or the API call fails.
    """
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    try:
        requests.post(
            url,
            data={
                "chat_id": chat_id,
                "text": message,
            },
            timeout=5,
        )
    except requests.RequestException:
        # Silent failure is intentional for non-blocking alert delivery.
        return
