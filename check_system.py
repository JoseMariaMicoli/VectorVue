
/*
Copyright (c) 2026 José María Micoli
Licensed under Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Remove copyright notices
*/

import sys
import os
from pathlib import Path
from time import sleep

# Colors
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def log(msg, status=True):
    mark = f"{GREEN}[PASS]{RESET}" if status else f"{RED}[FAIL]{RESET}"
    print(f"{mark} {msg}")

def check_dependencies():
    print("--- CHECKING DEPENDENCIES ---")
    required = ["textual", "cryptography", "rich"]
    all_good = True
    for req in required:
        try:
            __import__(req)
            log(f"Module found: {req}")
        except ImportError:
            log(f"Missing module: {req}", False)
            all_good = False
    return all_good

def check_fs_io():
    print("\n--- CHECKING ATOMIC FILESYSTEM ---")
    try:
        from vv_fs import FileSystemService
        test_path = Path("test_atomic_check.tmp")
        content = "ATOMIC_WRITE_TEST_DATA"
        
        # Test Write
        FileSystemService.atomic_write(test_path, content)
        if not test_path.exists():
            log("File write check", False)
            return False
        
        # Test Read
        status, read_content, _ = FileSystemService.read_file(test_path)
        if status and read_content == content:
            log("Atomic Write & Read integrity")
        else:
            log("Read content mismatch", False)
            return False
            
        # Test Delete
        FileSystemService.delete_node(test_path)
        if not test_path.exists():
            log("Delete node check")
        else:
            log("Delete failed", False)
            return False
            
        return True
    except ImportError:
        log("Could not import vv_fs", False)
        return False
    except Exception as e:
        log(f"FS Exception: {e}", False)
        return False

def check_crypto_chain():
    print("\n--- CHECKING CRYPTO ENGINE (KDF) ---")
    try:
        from vv_core import Database
        # Init DB in memory logic or just test methods
        db = Database()
        passphrase = "TEST_PASSWORD_123"
        
        # 1. Initialize Session (Derive Key)
        success = db.initialize_session(passphrase)
        if success:
            log("KDF Key Derivation (PBKDF2HMAC)")
        else:
            log("KDF Initialization failed", False)
            return False
            
        # 2. Test Encrypt/Decrypt
        plaintext = "CONFIDENTIAL_PAYLOAD"
        ciphertext = db.crypto.encrypt(plaintext)
        
        if ciphertext != plaintext and "gAAAA" in ciphertext:
            log("Encryption entropy check")
        else:
            log("Encryption failed or returned plaintext", False)
            return False
            
        decrypted = db.crypto.decrypt(ciphertext)
        if decrypted == plaintext:
            log("Decryption integrity check")
        else:
            log("Decryption result mismatch", False)
            return False
            
        return True
    except Exception as e:
        log(f"Crypto Exception: {e}", False)
        return False

if __name__ == "__main__":
    print(f"VECTORVUE SYSTEM CHECK [PID: {os.getpid()}]")
    s1 = check_dependencies()
    s2 = check_fs_io()
    s3 = check_crypto_chain()
    
    if s1 and s2 and s3:
        print(f"\n{GREEN}>>> SYSTEM GREEN. READY FOR TACTICAL DEPLOYMENT.{RESET}")
        sys.exit(0)
    else:
        print(f"\n{RED}>>> SYSTEM HALT. ERRORS DETECTED.{RESET}")
        sys.exit(1)