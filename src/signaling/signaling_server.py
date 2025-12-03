#!/usr/bin/env python3
"""
Сигналинг-сервер для Zvonilka.

Фичи:
  * RSA-аутентификация, токены.
  * Пользователи и их пароли зашиты в коде (USERS).
  * Хранение публичных ключей клиента (DER, SubjectPublicKeyInfo).
  * PUBKEY: выдача публичного ключа любого пользователя.
  * KEY_PUSH / KEY_POLL: буфер обмена RSA-зашифрованными AES-ключами
    (ключ зашифрован публичным ключом получателя, сервер его не видит).
  * ICE_OFFER / ICE_POLL_OFFER / ICE_ANSWER / ICE_POLL_ANSWER:
    буфер обмена ICE-параметрами, зашифрованными RSA ключом получателя.

Протокол (строки TCP, '\n'-terminated):

  GETPUB
    -> PUB <b64_der_server_pub>

  AUTH <b64_der_client_pub> <b64_cipher(creds)>
    creds = "user:pass" (UTF-8), зашифрованы серверным ключом
           (RSA OAEP SHA512)
    <- OK <b64_cipher(token)>
       token шифруется клиентским pub

  PUBKEY <token> <user>
    -> OK <b64_der_client_pub> | ERR notfound | ERR auth

  KEY_PUSH <token> <target_user> <b64_cipher_aes_key_for_target>
    (cipher_aes_key_for_target зашифрован публичным ключом target_user,
     сервер не может его расшифровать)
    -> OK | ERR auth

  KEY_POLL <token>
    -> OK <from_user> <b64_cipher_aes_key_for_me> | EMPTY | ERR auth

  ICE_OFFER <token> <target_user> <b64_cipher_ice_blob_for_target>
  ICE_POLL_OFFER <token>
    -> OK <from_user> <b64_cipher_ice_blob_for_me> | EMPTY | ERR auth

  ICE_ANSWER <token> <target_user> <b64_cipher_ice_blob_for_target>
  ICE_POLL_ANSWER <token>
    -> OK <from_user> <b64_cipher_ice_blob_for_me> | EMPTY | ERR auth
"""

import asyncio
import base64
import os
from collections import defaultdict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

# --- простейшая "база" пользователей (логин -> пароль) ---
USERS: dict[str, str] = {
    "user1": "pass123",
    "user2": "pass123",
}

# token -> (user, client_pubkey)
TOKENS: dict[str, tuple[str, PublicKeyTypes]] = {}

# user -> latest client_pubkey
USER_PUBKEY: dict[str, PublicKeyTypes] = {}

# user -> list[(from_user, keyCipherB64)]
KEY_MESSAGES: dict[str, list[tuple[str, str]]] = defaultdict(list)

# user -> list[(from_user, iceBlobB64)]
ICE_OFFERS: dict[str, list[tuple[str, str]]] = defaultdict(list)
ICE_ANSWERS: dict[str, list[tuple[str, str]]] = defaultdict(list)

# серверный ключ
SERVER_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def server_pub_der_b64() -> str:
    der = SERVER_KEY.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return b64e(der)


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    print(f"[sig] client connected: {peer}")

    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            text = line.decode(errors="ignore").strip()
            if not text:
                continue

            parts = text.split()
            cmd = parts[0].upper()
            print(f"[sig] cmd={parts}")

            # --- GETPUB ---
            if cmd == "GETPUB":
                writer.write(f"PUB {server_pub_der_b64()}\n".encode())
                await writer.drain()
                continue

            # --- AUTH ---
            if cmd == "AUTH" and len(parts) == 3:
                b64_client_pub, b64_cred = parts[1], parts[2]
                try:
                    client_pub = serialization.load_der_public_key(b64d(b64_client_pub))
                    cipher = b64d(b64_cred)
                    plain = SERVER_KEY.decrypt(
                        cipher,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA512()),
                            algorithm=hashes.SHA512(),
                            label=None,
                        ),
                    )
                    creds = plain.decode("utf-8", errors="strict")
                    if ":" not in creds:
                        raise ValueError("bad creds format")
                    user, pwd = creds.split(":", 1)
                    if USERS.get(user) != pwd:
                        print(f"[sig] AUTH bad creds for user={user!r}")
                        writer.write(b"ERR auth\n")
                        await writer.drain()
                        continue

                    token = os.urandom(16).hex()
                    TOKENS[token] = (user, client_pub)
                    USER_PUBKEY[user] = client_pub

                    cipher_token = client_pub.encrypt(
                        token.encode("ascii"),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA512()),
                            algorithm=hashes.SHA512(),
                            label=None,
                        ),
                    )
                    writer.write(f"OK {b64e(cipher_token)}\n".encode())
                except Exception as e:  # noqa: BLE001
                    print(f"[sig] AUTH error: {e!r}")
                    writer.write(b"ERR auth\n")
                await writer.drain()
                continue

            # --- от этой точки все команды требуют валидного token ---
            if cmd in {
                "PUBKEY",
                "KEY_PUSH",
                "KEY_POLL",
                "ICE_OFFER",
                "ICE_POLL_OFFER",
                "ICE_ANSWER",
                "ICE_POLL_ANSWER",
            }:
                # token всегда parts[1]
                if len(parts) < 2:
                    writer.write(b"ERR auth\n")
                    await writer.drain()
                    continue
                token = parts[1]
                if token not in TOKENS:
                    print(f"[sig] {cmd} auth failed (bad token)")
                    writer.write(b"ERR auth\n")
                    await writer.drain()
                    continue
                user, client_pub = TOKENS[token]

                # --- PUBKEY ---
                if cmd == "PUBKEY" and len(parts) == 3:
                    target = parts[2]
                    if target not in USER_PUBKEY:
                        print(f"[sig] PUBKEY miss {target}")
                        writer.write(b"ERR notfound\n")
                        await writer.drain()
                        continue
                    pub = USER_PUBKEY[target]
                    der = pub.public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    writer.write(f"OK {b64e(der)}\n".encode())
                    await writer.drain()
                    continue

                # --- KEY_PUSH ---
                if cmd == "KEY_PUSH" and len(parts) == 4:
                    target, key_cipher_b64 = parts[2], parts[3]
                    KEY_MESSAGES[target].append((user, key_cipher_b64))
                    print(f"[sig] KEY_PUSH from {user} -> {target}")
                    writer.write(b"OK\n")
                    await writer.drain()
                    continue

                # --- KEY_POLL ---
                if cmd == "KEY_POLL" and len(parts) == 2:
                    queue = KEY_MESSAGES[user]
                    if queue:
                        from_user, key_cipher_b64 = queue.pop(0)
                        print(f"[sig] KEY_POLL deliver to {user} from {from_user}")
                        writer.write(f"OK {from_user} {key_cipher_b64}\n".encode())
                    else:
                        writer.write(b"EMPTY\n")
                    await writer.drain()
                    continue

                # --- ICE_OFFER ---
                if cmd == "ICE_OFFER" and len(parts) == 4:
                    target, blob_b64 = parts[2], parts[3]
                    ICE_OFFERS[target].append((user, blob_b64))
                    print(f"[sig] ICE_OFFER from {user} -> {target}")
                    writer.write(b"OK\n")
                    await writer.drain()
                    continue

                # --- ICE_POLL_OFFER ---
                if cmd == "ICE_POLL_OFFER" and len(parts) == 2:
                    queue = ICE_OFFERS[user]
                    if queue:
                        from_user, blob_b64 = queue.pop(0)
                        print(
                            f"[sig] ICE_POLL_OFFER deliver to {user} from {from_user}"
                        )
                        writer.write(f"OK {from_user} {blob_b64}\n".encode())
                    else:
                        writer.write(b"EMPTY\n")
                    await writer.drain()
                    continue

                # --- ICE_ANSWER ---
                if cmd == "ICE_ANSWER" and len(parts) == 4:
                    target, blob_b64 = parts[2], parts[3]
                    ICE_ANSWERS[target].append((user, blob_b64))
                    print(f"[sig] ICE_ANSWER from {user} -> {target}")
                    writer.write(b"OK\n")
                    await writer.drain()
                    continue

                # --- ICE_POLL_ANSWER ---
                if cmd == "ICE_POLL_ANSWER" and len(parts) == 2:
                    queue = ICE_ANSWERS[user]
                    if queue:
                        from_user, blob_b64 = queue.pop(0)
                        print(
                            f"[sig] ICE_POLL_ANSWER deliver to {user} from {from_user}"
                        )
                        writer.write(f"OK {from_user} {blob_b64}\n".encode())
                    else:
                        writer.write(b"EMPTY\n")
                    await writer.drain()
                    continue

            # неизвестная команда
            writer.write(b"ERR badcmd\n")
            await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        print(f"[sig] client disconnected: {peer}")


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 7777)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"Signaling server listening on {addrs}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
