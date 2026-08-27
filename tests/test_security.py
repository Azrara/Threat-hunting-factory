"""Password handling, tokens and access control primitives."""

from __future__ import annotations

import time

import pytest

from app.security import create_access_token, decode_access_token, hash_password, verify_password


class TestPasswords:
    def test_hash_and_verify(self):
        digest = hash_password("CorrectHorseBattery1")
        assert digest != "CorrectHorseBattery1"
        assert verify_password("CorrectHorseBattery1", digest)
        assert not verify_password("WrongPassword1", digest)

    def test_hashes_are_salted(self):
        assert hash_password("SamePassword1") != hash_password("SamePassword1")

    @pytest.mark.parametrize("password", ["", "short", "1234567"])
    def test_short_passwords_are_refused(self, password):
        with pytest.raises(ValueError):
            hash_password(password)

    def test_long_passwords_are_accepted(self):
        long_password = "x" * 200
        assert verify_password(long_password, hash_password(long_password))

    def test_a_corrupt_hash_never_verifies(self):
        assert not verify_password("anything", "not-a-real-hash")


class TestTokens:
    def test_round_trip(self):
        token = create_access_token("user-1", "tenant-1", "admin")
        payload = decode_access_token(token)
        assert payload["sub"] == "user-1"
        assert payload["tid"] == "tenant-1"
        assert payload["role"] == "admin"
        assert payload["exp"] > time.time()

    @pytest.mark.parametrize("token", ["", "abc", "a.b.c", "not.a.token"])
    def test_invalid_tokens_are_rejected(self, token):
        assert decode_access_token(token) is None

    def test_a_tampered_token_is_rejected(self):
        token = create_access_token("user-1", "tenant-1", "viewer")
        head, body, signature = token.split(".")
        forged = f"{head}.{body}.{signature[:-4]}AAAA"
        assert decode_access_token(forged) is None

    def test_a_token_from_another_secret_is_rejected(self):
        import jwt

        foreign = jwt.encode({"sub": "user-1", "tid": "tenant-1", "role": "admin"},
                             "a-different-secret-that-is-long-enough-000000", algorithm="HS256")
        assert decode_access_token(foreign) is None
