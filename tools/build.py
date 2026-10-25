"""Шифрует src/<логин>.json -> data/<логин>.enc.json по паролям из src/passwords.json.
Запуск: python tools/build.py   (нужен пакет cryptography)"""
import json, os, base64
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
b = lambda x: base64.b64encode(x).decode()
pw = json.load(open(f"{root}/src/passwords.json", encoding="utf-8"))
os.makedirs(f"{root}/data", exist_ok=True)
for u, p in pw.items():
    raw = open(f"{root}/src/{u}.json", "rb").read()
    salt, iv = os.urandom(16), os.urandom(12)
    key = pbkdf2_hmac("sha256", p.encode(), salt, 200000, 32)
    json.dump({"s": b(salt), "i": b(iv), "c": b(AESGCM(key).encrypt(iv, raw, None))},
              open(f"{root}/data/{u}.enc.json", "w"))
    print("ok", u)
