#!/usr/bin/env python3
"""Password Hashing Demonstration - educational CLI using PBKDF2-HMAC-SHA256."""

import hashlib
import hmac
import secrets

ITERATIONS = 600_000
SALT_BYTES = 16
HASH_BYTES = 32


def hash_password(password: str) -> tuple[str, str]:
    """Return (salt_hex, hash_hex) for a password using PBKDF2."""
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=HASH_BYTES
    )
    return salt.hex(), derived.hex()


def verify_password(password: str, salt_hex: str, stored_hash_hex: str) -> bool:
    """Verify a password against its salt and stored hash."""
    try:
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(stored_hash_hex)
    except ValueError:
        return False

    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=len(stored_hash)
    )
    return hmac.compare_digest(candidate, stored_hash)



def main() -> None:
    print("=" * 48)
    print("       PASSWORD HASHING DEMONSTRATION")
    print("=" * 48)
    password = input("Enter a password to hash: ")
    salt, digest = hash_password(password)


    print("\nGenerated result")
    print(f"Algorithm : PBKDF2-HMAC-SHA256 ({ITERATIONS:,} iterations)")
    print(f"Salt     : {salt}")
    print(f"Hash     : {digest}")

    print("\nVerify a password")
    attempt = input("Enter password again: ")
    if verify_password(attempt, salt, digest):
        print("Result   : Password matches.")
    else:
        print("Result   : Password does NOT match.")

    print("\nEducational note: this demo does not save your password or hash to disk.")



if __name__ == "__main__":
    main()
