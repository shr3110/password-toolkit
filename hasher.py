"""
hasher.py - Password hashing utilities using bcrypt and hashlib
"""

import bcrypt
import hashlib
from typing import Tuple


class PasswordHasher:
    """Handles password hashing operations with bcrypt and SHA-256"""

    def __init__(self, rounds: int = 12):
        """
        Initialize the PasswordHasher

        Args:
            rounds: Cost factor for bcrypt (default: 12, range: 4-31)
                   Higher values = more secure but slower
        """
        if rounds < 4 or rounds > 31:
            raise ValueError("Rounds must be between 4 and 31")
        self.rounds = rounds

    def hash_password_bcrypt(self, password: str) -> str:
        """
        Hash a password using bcrypt (recommended method)

        Args:
            password: Plain text password to hash

        Returns:
            Bcrypt hashed password as string
        """
        # Convert password to bytes
        password_bytes = password.encode('utf-8')

        # Generate salt and hash
        salt = bcrypt.gensalt(rounds=self.rounds)
        hashed = bcrypt.hashpw(password_bytes, salt)

        # Return as string for storage
        return hashed.decode('utf-8')

    def verify_password_bcrypt(self, password: str, hashed_password: str) -> bool:
        """
        Verify a password against a bcrypt hash

        Args:
            password: Plain text password to verify
            hashed_password: Stored bcrypt hash

        Returns:
            True if password matches, False otherwise
        """
        password_bytes = password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')

        return bcrypt.checkpw(password_bytes, hashed_bytes)

    def hash_password_sha256(self, password: str, salt: str = None) -> Tuple[str, str]:
        """
        Hash a password using SHA-256 with salt (for demonstration purposes)
        Note: bcrypt is preferred for password hashing

        Args:
            password: Plain text password to hash
            salt: Optional salt (will be generated if not provided)

        Returns:
            Tuple of (hashed_password, salt)
        """
        if salt is None:
            # Generate random salt
            salt = bcrypt.gensalt().decode('utf-8')

        # Combine password and salt
        salted_password = (password + salt).encode('utf-8')

        # Hash using SHA-256
        hashed = hashlib.sha256(salted_password).hexdigest()

        return hashed, salt

    def verify_password_sha256(self, password: str, hashed_password: str, salt: str) -> bool:
        """
        Verify a password against a SHA-256 hash

        Args:
            password: Plain text password to verify
            hashed_password: Stored SHA-256 hash
            salt: Salt used during hashing

        Returns:
            True if password matches, False otherwise
        """
        # Hash the provided password with the same salt
        test_hash, _ = self.hash_password_sha256(password, salt)

        return test_hash == hashed_password

    def hash_password_multiple_rounds(self, password: str, iterations: int = 10000) -> str:
        """
        Hash a password using SHA-256 with multiple iterations (PBKDF2-like)

        Args:
            password: Plain text password to hash
            iterations: Number of hash iterations

        Returns:
            Hashed password
        """
        # Use hashlib's pbkdf2 for proper key derivation
        salt = bcrypt.gensalt()
        hashed = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )

        # Return hash + salt (separated by $)
        return f"{hashed.hex()}${salt.decode('utf-8')}"

    def get_hash_info(self, bcrypt_hash: str) -> dict:
        """
        Extract information from a bcrypt hash

        Args:
            bcrypt_hash: Bcrypt hash string

        Returns:
            Dictionary with hash algorithm and cost factor
        """
        try:
            # Bcrypt format: $2b$rounds$salt+hash
            parts = bcrypt_hash.split('$')
            return {
                'algorithm': parts[1] if len(parts) > 1 else 'unknown',
                'rounds': int(parts[2]) if len(parts) > 2 else 0,
                'valid_format': len(parts) == 4
            }
        except (IndexError, ValueError):
            return {
                'algorithm': 'unknown',
                'rounds': 0,
                'valid_format': False
            }


# Utility functions for quick access
def hash_password(password: str, rounds: int = 12) -> str:
    """Quick function to hash a password with bcrypt"""
    hasher = PasswordHasher(rounds=rounds)
    return hasher.hash_password_bcrypt(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Quick function to verify a password against bcrypt hash"""
    hasher = PasswordHasher()
    return hasher.verify_password_bcrypt(password, hashed_password)


if __name__ == "__main__":
    # Demo usage
    print("=== Password Hashing Demo ===\n")

    hasher = PasswordHasher(rounds=12)

    # Bcrypt example
    test_password = "MySecureP@ssw0rd123"
    print(f"Original password: {test_password}")

    bcrypt_hash = hasher.hash_password_bcrypt(test_password)
    print(f"\nBcrypt hash: {bcrypt_hash}")
    print(f"Hash info: {hasher.get_hash_info(bcrypt_hash)}")

    # Verify correct password
    is_valid = hasher.verify_password_bcrypt(test_password, bcrypt_hash)
    print(f"\nVerify correct password: {is_valid}")

    # Verify wrong password
    is_valid = hasher.verify_password_bcrypt("WrongPassword", bcrypt_hash)
    print(f"Verify wrong password: {is_valid}")

    # SHA-256 example (for comparison)
    print("\n=== SHA-256 with Salt (for demonstration) ===")
    sha_hash, salt = hasher.hash_password_sha256(test_password)
    print(f"SHA-256 hash: {sha_hash}")
    print(f"Salt: {salt}")

    is_valid = hasher.verify_password_sha256(test_password, sha_hash, salt)
    print(f"Verify correct password: {is_valid}")