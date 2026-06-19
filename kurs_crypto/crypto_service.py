from __future__ import annotations

import base64
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Optional

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


MAGIC = b"KURSMAILENC"
VERSION = 1
HEADER_LEN_SIZE = 4
TAG_SIZE = 16
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
DEFAULT_ITERATIONS = 300_000
CHUNK_SIZE = 1024 * 1024


class CryptoFormatError(ValueError):
    pass


def encrypt_file(
    source_path: str | Path,
    password: str,
    output_path: Optional[str | Path] = None,
    *,
    iterations: int = DEFAULT_ITERATIONS,
) -> Path:
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"Исходный файл не найден: {source}")
    _validate_password(password)
    if iterations < 100_000:
        raise ValueError("Число итераций PBKDF2 должно быть не менее 100000")

    destination = Path(output_path) if output_path else source.with_name(source.name + ".aes256")
    salt = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)
    key = _derive_key(password, salt, iterations)

    header = _build_header(source.name, salt, nonce, iterations)
    header_bytes = _serialize_header(header)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
    cipher.update(header_bytes)

    with source.open("rb") as src, destination.open("wb") as dst:
        _write_file_prefix(dst, header_bytes)
        _copy_encrypted(src, dst, cipher)
        dst.write(cipher.digest())

    return destination


def decrypt_file(
    encrypted_path: str | Path,
    password: str,
    output_path: Optional[str | Path] = None,
) -> Path:
    source = Path(encrypted_path)
    if not source.is_file():
        raise FileNotFoundError(f"Зашифрованный файл не найден: {source}")
    _validate_password(password)

    with source.open("rb") as src:
        header_bytes, header = _read_file_prefix(src)
        salt = _b64decode_required(header, "salt")
        nonce = _b64decode_required(header, "nonce")
        iterations = int(header["iterations"])
        key = _derive_key(password, salt, iterations)

        destination = _resolve_decryption_output(source, header, output_path)
        temp_destination = destination.with_name(destination.name + ".tmp")

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
        cipher.update(header_bytes)

        try:
            _copy_decrypted(src, temp_destination, cipher)
        except Exception:
            temp_destination.unlink(missing_ok=True)
            raise

    temp_destination.replace(destination)
    return destination


def _validate_password(password: str) -> None:
    if not password:
        raise ValueError("Пароль не должен быть пустым")


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=KEY_SIZE,
        count=iterations,
        hmac_hash_module=SHA256,
    )


def _build_header(original_name: str, salt: bytes, nonce: bytes, iterations: int) -> dict[str, object]:
    return {
        "algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "original_name": original_name,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _serialize_header(header: dict[str, object]) -> bytes:
    return json.dumps(header, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _write_file_prefix(dst: BinaryIO, header_bytes: bytes) -> None:
    dst.write(MAGIC)
    dst.write(bytes([VERSION]))
    dst.write(struct.pack(">I", len(header_bytes)))
    dst.write(header_bytes)


def _read_file_prefix(src: BinaryIO) -> tuple[bytes, dict[str, object]]:
    if src.read(len(MAGIC)) != MAGIC:
        raise CryptoFormatError("Неподдерживаемый формат зашифрованного файла")

    version = src.read(1)
    if version != bytes([VERSION]):
        raise CryptoFormatError("Неподдерживаемая версия зашифрованного файла")

    header_len_bytes = src.read(HEADER_LEN_SIZE)
    if len(header_len_bytes) != HEADER_LEN_SIZE:
        raise CryptoFormatError("Заголовок зашифрованного файла неполный")

    header_len = struct.unpack(">I", header_len_bytes)[0]
    if header_len <= 0 or header_len > 64 * 1024:
        raise CryptoFormatError("Заголовок зашифрованного файла имеет некорректную длину")

    header_bytes = src.read(header_len)
    if len(header_bytes) != header_len:
        raise CryptoFormatError("Заголовок зашифрованного файла поврежден")

    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CryptoFormatError("Заголовок зашифрованного файла не является корректным JSON") from exc

    _validate_header(header)
    return header_bytes, header


def _validate_header(header: object) -> None:
    if not isinstance(header, dict):
        raise CryptoFormatError("Заголовок зашифрованного файла должен быть объектом")

    required = {"algorithm", "kdf", "iterations", "salt", "nonce", "original_name", "created_utc"}
    missing = required.difference(header)
    if missing:
        raise CryptoFormatError(f"В заголовке зашифрованного файла отсутствуют поля: {', '.join(sorted(missing))}")

    if header["algorithm"] != "AES-256-GCM" or header["kdf"] != "PBKDF2-HMAC-SHA256":
        raise CryptoFormatError("Неподдерживаемые криптографические параметры")

    try:
        iterations = int(header["iterations"])
    except (TypeError, ValueError) as exc:
        raise CryptoFormatError("Некорректное число итераций PBKDF2") from exc

    if iterations < 100_000:
        raise CryptoFormatError("Число итераций PBKDF2 слишком мало")

    if len(_b64decode_required(header, "salt")) != SALT_SIZE:
        raise CryptoFormatError("Некорректный размер salt")
    if len(_b64decode_required(header, "nonce")) != NONCE_SIZE:
        raise CryptoFormatError("Некорректный размер nonce")


def _b64decode_required(header: dict[str, object], field: str) -> bytes:
    try:
        return base64.b64decode(str(header[field]).encode("ascii"), validate=True)
    except Exception as exc:
        raise CryptoFormatError(f"Поле заголовка '{field}' не является корректным base64") from exc


def _copy_encrypted(src: BinaryIO, dst: BinaryIO, cipher) -> None:
    while True:
        chunk = src.read(CHUNK_SIZE)
        if not chunk:
            break
        dst.write(cipher.encrypt(chunk))


def _copy_decrypted(src: BinaryIO, destination: Path, cipher) -> None:
    encrypted_payload = src.read()
    if len(encrypted_payload) < TAG_SIZE:
        raise CryptoFormatError("Зашифрованный файл не содержит тег аутентификации")

    ciphertext = encrypted_payload[:-TAG_SIZE]
    tag = encrypted_payload[-TAG_SIZE:]

    with destination.open("wb") as dst:
        for start in range(0, len(ciphertext), CHUNK_SIZE):
            dst.write(cipher.decrypt(ciphertext[start : start + CHUNK_SIZE]))
        cipher.verify(tag)


def _resolve_decryption_output(
    encrypted_path: Path,
    header: dict[str, object],
    output_path: Optional[str | Path],
) -> Path:
    if output_path:
        return Path(output_path)

    original_name = os.path.basename(str(header["original_name"])) or "расшифрованное_вложение"
    if encrypted_path.name.endswith(".aes256"):
        candidate = encrypted_path.with_name(encrypted_path.name[: -len(".aes256")])
        if candidate.name == original_name:
            return candidate

    return encrypted_path.with_name(original_name)
