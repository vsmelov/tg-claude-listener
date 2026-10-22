#!/usr/bin/env python3
"""One-time login: creates sessions/desktop.session for the listener.

Asks for your phone number, the code Telegram sends you, and the 2FA password if you have one.
Run it yourself in a terminal (not through Claude):  python login.py
The session file is a key to your Telegram account - never send it to anyone.
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from telethon import TelegramClient

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
api_id, api_hash = os.environ.get("TELEGRAM_API_ID"), os.environ.get("TELEGRAM_API_HASH")
if not api_id or not api_hash:
    sys.exit("Fill TELEGRAM_API_ID and TELEGRAM_API_HASH in .env first (copy .env.example)")
(ROOT / "sessions").mkdir(exist_ok=True)
client = TelegramClient(str(ROOT / "sessions" / "desktop"), int(api_id), api_hash)
with client:
    me = client.get_me()
    print(f"OK, logged in as {me.first_name} (@{me.username}), id {me.id}")
    print("Session saved to sessions/desktop.session")
