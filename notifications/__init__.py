"""Notification utilities for Telegram, Discord, etc."""

import aiohttp
from typing import Optional


async def send_telegram_message(token: str, chat_id: str, message: str) -> bool:
    """Send message via Telegram bot."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as resp:
                return resp.status == 200
    except Exception:
        return False


async def send_discord_message(webhook_url: str, message: str, username: str = "Network Scanner") -> bool:
    """Send message via Discord webhook."""
    payload = {"content": message, "username": username}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload) as resp:
                return resp.status == 204
    except Exception:
        return False
