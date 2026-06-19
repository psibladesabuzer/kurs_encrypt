from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from kurs_crypto.crypto_service import CryptoFormatError, decrypt_file, encrypt_file


class CryptoServiceTests(unittest.TestCase):
    def test_шифрование_и_расшифрование_файла(self) -> None:
        with TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "вложение.txt"
            encrypted = Path(temp_dir) / "вложение.txt.aes256"
            decrypted = Path(temp_dir) / "вложение.расшифровано.txt"
            source.write_text("секретное вложение\nданные курсового проекта", encoding="utf-8")

            result = encrypt_file(source, "надежный пароль для проверки", encrypted, iterations=100_000)
            self.assertEqual(result, encrypted)
            self.assertTrue(encrypted.exists())
            self.assertNotEqual(encrypted.read_bytes(), source.read_bytes())

            restored = decrypt_file(encrypted, "надежный пароль для проверки", decrypted)
            self.assertEqual(restored, decrypted)
            self.assertEqual(decrypted.read_text(encoding="utf-8"), source.read_text(encoding="utf-8"))

    def test_неверный_пароль_не_создает_результат(self) -> None:
        with TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "фото.bin"
            encrypted = Path(temp_dir) / "фото.bin.aes256"
            decrypted = Path(temp_dir) / "фото.bin"
            source.write_bytes(b"\x00\x01\x02" * 100)

            encrypt_file(source, "надежный пароль", encrypted, iterations=100_000)
            source.unlink()

            with self.assertRaises(ValueError):
                decrypt_file(encrypted, "неверный пароль", decrypted)
            self.assertFalse(decrypted.exists())

    def test_измененный_шифртекст_отклоняется(self) -> None:
        with TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "данные.txt"
            encrypted = Path(temp_dir) / "данные.txt.aes256"
            decrypted = Path(temp_dir) / "данные.результат.txt"
            source.write_text("полезная нагрузка", encoding="utf-8")
            encrypt_file(source, "надежный пароль", encrypted, iterations=100_000)

            payload = bytearray(encrypted.read_bytes())
            payload[-20] ^= 0x01
            encrypted.write_bytes(payload)

            with self.assertRaises(ValueError):
                decrypt_file(encrypted, "надежный пароль", decrypted)
            self.assertFalse(decrypted.exists())

    def test_неверная_сигнатура_формата_отклоняется(self) -> None:
        with TemporaryDirectory() as temp_dir:
            encrypted = Path(temp_dir) / "ошибка.aes256"
            encrypted.write_bytes("не зашифровано".encode("utf-8"))

            with self.assertRaises(CryptoFormatError):
                decrypt_file(encrypted, "надежный пароль", Path(temp_dir) / "результат.txt")


if __name__ == "__main__":
    unittest.main()
