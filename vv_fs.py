# --- START OF FILE vv_fs.py ---

import os
import shutil
import tempfile
from pathlib import Path
from typing import Tuple, Union

class FileSystemService:
    """
    VectorVue v2.3: Critical I/O Abstraction Layer.
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
                
            with tempfile.NamedTemporaryFile('w', dir=temp_dir, delete=False, encoding='utf-8') as tf:
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
                path.unlink()
            return True, "Deleted successfully"
        except Exception as e:
            return False, f"Delete failed: {str(e)}"

    @staticmethod
    def cleanup_temp_files():
        """Clean temp artifacts on exit"""
        pass