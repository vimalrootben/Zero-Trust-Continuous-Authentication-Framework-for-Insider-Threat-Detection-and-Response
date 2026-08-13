import pytest
from manager.auth.password_handler import PasswordHandler
from manager.auth.exceptions import WeakPasswordError

def test_password_strength_validation():
    ph = PasswordHandler()

    # Too short
    with pytest.raises(WeakPasswordError, match="at least 12 characters"):
        ph.hash_password("Ab1!")

    # No uppercase
    with pytest.raises(WeakPasswordError, match="uppercase letter"):
        ph.hash_password("weakpassword1!")

    # No lowercase
    with pytest.raises(WeakPasswordError, match="lowercase letter"):
        ph.hash_password("WEAKPASSWORD1!")

    # No digit
    with pytest.raises(WeakPasswordError, match="digit"):
        ph.hash_password("WeakPassword!")

    # No symbol
    with pytest.raises(WeakPasswordError, match="special character/symbol"):
        ph.hash_password("WeakPassword123")

    # Meets all requirements
    hashed = ph.hash_password("AdminSecure123!")
    assert hashed.startswith("$argon2id$")


def test_password_verification():
    ph = PasswordHandler()
    plain = "AdminSecure123!"
    hashed = ph.hash_password(plain)

    # Valid verify
    assert ph.verify_password(plain, hashed) is True

    # Invalid verify
    assert ph.verify_password("WrongPassword123!", hashed) is False
    assert ph.verify_password(plain, "invalid_hash_string") is False
