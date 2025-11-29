#!/usr/bin/env python3
"""
Сигналинг-сервер с аутентификацией по RSA.

Протокол (строки TCP):
  GETPUB
    -> PUB <b64_der_server_pub>
  AUTH <b64_der_client_pub> <b64_cipher(creds)>
    creds = "user:pass", зашифрованы серверным ключом (RSA OAEP SHA256)
    <- OK <b64_cipher(token)>  (token шифруется клиентским pub)
  REGISTER <token> <ip> <port>
    token должен быть выдан при AUTH; сохраняет адрес вызывающего
    -> OK | ERR auth | ERR badport
  QUERY <token> <user>
    token проверяем; ищем адрес user, возвращаем
    -> OK <ip> <port> | ERR notfound | ERR auth

База пользователей USERS хардкодится ниже.
"""

import asyncio
import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

USERS: dict[str, str] = {
    "user1": "pass123",
    "user2": "pass123",
}

# user -> (ip, port)
REGISTRY: dict[str, tuple[str, int]] = {}
# token -> (user, client_pub)
TOKENS: dict[str, tuple[str, PublicKeyTypes]] = {}

SERVER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode())


def server_pub_der_b64() -> str:
    der = SERVER_KEY.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64e(der)


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            parts = line.decode().strip().split()
            if not parts:
                continue
            cmd = parts[0].upper()
            print(f"[sig] cmd={parts}")

            if cmd == "GETPUB":
                writer.write(f"PUB {server_pub_der_b64()}\n".encode())
                await writer.drain()
                continue

            if cmd == "AUTH" and len(parts) == 3:
                b64_client_pub, b64_cred = parts[1], parts[2]
                try:
                    client_pub = serialization.load_der_public_key(b64d(b64_client_pub))
                    cipher = b64d(b64_cred)
                    plain = SERVER_KEY.decrypt(
                        cipher,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    creds = plain.decode()
                    if ":" not in creds:
                        raise ValueError("bad creds format")
                    user, pwd = creds.split(":", 1)
                    if USERS.get(user) != pwd:
                        print(f"[sig] AUTH bad creds for user={user}")
                        writer.write(b"ERR auth\n")
                        await writer.drain()
                        continue
                    token = os.urandom(16).hex()
                    TOKENS[token] = (user, client_pub)
                    cipher_token = client_pub.encrypt(
                        token.encode(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    writer.write(f"OK {b64e(cipher_token)}\n".encode())
                except Exception:
                    writer.write(b"ERR auth\n")
                await writer.drain()
                continue

            if cmd == "REGISTER" and len(parts) == 4:
                token, ip, port_s = parts[1], parts[2], parts[3]
                if token not in TOKENS:
                    print("[sig] REGISTER auth failed")
                    writer.write(b"ERR auth\n")
                    await writer.drain()
                    continue
                try:
                    port = int(port_s)
                except ValueError:
                    print("[sig] REGISTER bad port")
                    writer.write(b"ERR badport\n")
                    await writer.drain()
                    continue
                user, _ = TOKENS[token]
                REGISTRY[user] = (ip, port)
                print(f"[sig] REGISTER ok user={user} {ip}:{port}")
                writer.write(b"OK\n")
                await writer.drain()
                continue

            if cmd == "QUERY" and len(parts) == 3:
                token, target = parts[1], parts[2]
                if token not in TOKENS:
                    print("[sig] QUERY auth failed")
                    writer.write(b"ERR auth\n")
                    await writer.drain()
                    continue
                if target in REGISTRY:
                    ip, port = REGISTRY[target]
                    print(f"[sig] QUERY hit {target} -> {ip}:{port}")
                    writer.write(f"OK {ip} {port}\n".encode())
                else:
                    print(f"[sig] QUERY miss {target}")
                    writer.write(b"ERR notfound\n")
                await writer.drain()
                continue

            writer.write(b"ERR badcmd\n")
            await writer.drain()
    finally:
        writer.close()


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 7777)
    print("Signaling server listening on 0.0.0.0:7777")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
