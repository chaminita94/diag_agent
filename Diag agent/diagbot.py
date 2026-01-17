#!/usr/bin/env python3
"""
diagbot.py - Independent Telegram Responder for Cybershield Diag Agent.
This script should be hosted on a dedicated Bot VM.
It helps users discover their Telegram Chat ID by responding to /start or /id commands.
"""

import os
import time
import requests

# Configure your Telegram bot token here or via environment variable
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8297536398:AAE-peeeFX7QFB92Hvs3rmwoffHrs1u16nw")

def send_telegram_message(chat_id, text):
    """Simple helper to send a text message."""
    if not TELEGRAM_BOT_TOKEN or not chat_id:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}, timeout=10)
    except Exception as e:
        print(f"[Error] Failed to send message: {e}")

def telegram_worker_loop():
    """Main polling loop for Telegram commands."""
    if not TELEGRAM_BOT_TOKEN:
        print("[Critical] No TELEGRAM_BOT_TOKEN found. Please set it and restart.")
        return
    
    print(f"[*] Cybershield Telegram Responder ACTIVE...")
    print(f"[*] Monitoring updates for /start and /id commands...")
    
    offset = None
    
    while True:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
            params = {"timeout": 30, "offset": offset}
            response = requests.get(url, params=params, timeout=35)
            
            if response.status_code != 200:
                print(f"[!] Telegram API error (Status {response.status_code})")
                time.sleep(10)
                continue
                
            r = response.json()
            if not r.get("ok"):
                print(f"[!] API Error: {r.get('description')}")
                time.sleep(10)
                continue
                
            for update in r.get("result", []):
                offset = update["update_id"] + 1
                msg = update.get("message", {})
                text = msg.get("text", "").strip().lower()
                chat = msg.get("chat", {})
                chat_id = chat.get("id")
                user = msg.get("from", {}).get("username", "unknown")
                
                print(f"[+] Received '{text}' from @{user} (ID: {chat_id})")
                
                if text.startswith("/start") or text.startswith("/id") or text.startswith("/help"):
                    reply = (
                        "🌟 *Cybershield Diag Agent Bot*\n\n"
                        "Your Telegram Chat ID is:\n"
                        f"`{chat_id}`\n\n"
                        "Copy this ID and paste it into the Diag Agent interface to receive your security reports."
                    )
                    send_telegram_message(chat_id, reply)
                    print(f"[+] Sent ID response to @{user}")
                    
        except KeyboardInterrupt:
            print("\n[!] Stopping bot...")
            break
        except Exception as e:
            print(f"[!] Loop error: {str(e)}")
            time.sleep(5)

if __name__ == "__main__":
    telegram_worker_loop()
