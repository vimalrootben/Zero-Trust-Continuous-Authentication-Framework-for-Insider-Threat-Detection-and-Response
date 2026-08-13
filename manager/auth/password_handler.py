import re
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from manager.auth.exceptions import WeakPasswordError

class PasswordHandler:
    """Handles password hashing, validation, and verification using Argon2id."""

    def __init__(self):
        # Default Argon2id parameters recommended by OWASP
        self.ph = PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16
        )

    def validate_password_strength(self, plain: str) -> None:
        """Enforces a password strength policy:
        - Minimum 12 characters.
        - Must contain at least one uppercase letter.
        - Must contain at least one lowercase letter.
        - Must contain at least one digit.
        - Must contain at least one special character/symbol.
        
        Raises WeakPasswordError if validation fails.
        """
        if len(plain) < 12:
            raise WeakPasswordError("Password must be at least 12 characters long.")
        if not re.search(r"[A-Z]", plain):
            raise WeakPasswordError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", plain):
            raise WeakPasswordError("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", plain):
            raise WeakPasswordError("Password must contain at least one digit.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", plain):
            raise WeakPasswordError("Password must contain at least one special character/symbol.")

    def hash_password(self, plain: str) -> str:
        """Hashes password using Argon2id.
        Raises WeakPasswordError if password does not meet requirements.
        """
        self.validate_password_strength(plain)
        return self.ph.hash(plain)

    def verify_password(self, plain: str, hashed: str) -> bool:
        """Verifies a plain password against an Argon2id hash.
        Returns True if correct, False otherwise.
        """
        try:
            return self.ph.verify(hashed, plain)
        except VerifyMismatchError:
            return False
        except Exception:
            return False
