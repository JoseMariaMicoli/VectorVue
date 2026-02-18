"""
Copyright (c) 2026 José María Micoli
Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
"""

import os
import shutil
import tempfile
import hashlib
from pathlib import Path
from typing import Tuple, Union

class FileSystemService:
    """
    VectorVue v2.5: Critical I/O Abstraction Layer.
    """

    @staticmethod
    def validate_path(path: Union[str, Path]) -> Path:
        return Path(path).resolve()

    @staticmethod
    def read_file(path: Path) -> Tuple[bool, str, str]:
        if not path.exists():
            return False, "File not found", ""
        try:
            if path.stat().st_size > 5_000_000:
                return False, "File too large (>5MB)", ""
        except OSError as e:
            return False, f"Stat Error: {e}", ""
        try:
            with open(path, "r", encoding="utf-8") as f:
                return True, f.read(), "utf-8"
        except Exception as e:
            return False, str(e), ""

    @staticmethod
    def atomic_write(path: Path, content: str) -> Tuple[bool, str]:
        try:
            temp_dir = path.parent
            if not temp_dir.exists():
                temp_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile('w', dir=temp_dir, delete=False,
                                             encoding='utf-8') as tf:
                tf.write(content)
                tf.flush()
                os.fsync(tf.fileno())
                temp_path = Path(tf.name)
            os.replace(temp_path, path)
            return True, f"Saved: {path.name}"
        except Exception as e:
            return False, f"Write Error: {e}"

    @staticmethod
    def create_node(path: Path, is_folder: bool) -> Tuple[bool, str]:
        if path.exists():
            return False, "Target already exists"
        try:
            if is_folder:
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.touch()
            return True, f"Created {path.name}"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def delete_node(path: Path) -> Tuple[bool, str]:
        if not path.exists():
            return False, "Path does not exist"
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                FileSystemService.secure_wipe(path)
                path.unlink()
            return True, "Deleted successfully"
        except Exception as e:
            return False, f"Delete failed: {str(e)}"

    @staticmethod
    def secure_wipe(path: Path, passes: int = 1):
        """
        Overwrites file with random data before deletion.
        Note: On SSDs with wear-leveling, multi-pass overwrite does not guarantee
        data destruction. Use full-disk encryption for strong at-rest guarantees.
        """
        try:
            length = path.stat().st_size
            with open(path, "wb") as f:
                for _ in range(passes):
                    f.write(os.urandom(length))
                    f.seek(0)
        except Exception:
            pass

    @staticmethod
    def calculate_file_hash(path: Path) -> str:
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    data = f.read(65536)
                    if not data:
                        break
                    sha256.update(data)
            return sha256.hexdigest()
        except Exception:
            return "HASH_ERROR"

    @staticmethod
    def ingest_c2_log(log_path: Path) -> Tuple[bool, str]:
        if not log_path.exists():
            return False, "Log file not found."
        try:
            with open(log_path, "r", errors="replace") as f:
                raw_data = f.read()
            formatted = (f"## C2 LOG INGESTION\n"
                         f"**Source:** {log_path.name}\n"
                         f"**Hash:** {FileSystemService.calculate_file_hash(log_path)}\n\n"
                         f"```text\n{raw_data}\n```")
            return True, formatted
        except Exception as e:
            return False, f"Ingestion Error: {e}"

    @staticmethod
    def ensure_delivery_dir():
        Path("05-Delivery").mkdir(exist_ok=True)

    @staticmethod
    def cleanup_temp_files():
        pass