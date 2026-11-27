from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from uuid import UUID

import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

AUTH_ROLES = frozenset({"ADMIN", "COMPANY", "STUDENT"})
REQUIRED_CLAIMS = (
    "iss",
    "aud",
    "sub",
    "jti",
    "iat",
    "nbf",
    "exp",
    "type",
    "email",
    "role",
    "is_active",
    "scope",
)


@dataclass(frozen=True)
class AuthIdentity:
    id: UUID
    email: str
    role: str
    scopes: frozenset[str]
    is_active = True
    is_authenticated = True


@lru_cache(maxsize=1)
def _verification_key(pem: str, path: Path) -> RSAPublicKey:
    key = load_pem_public_key(
        pem.replace("\\n", "\n").encode() if pem else path.read_bytes()
    )
    if not isinstance(key, RSAPublicKey) or key.key_size < 2048:
        raise ValueError("Expected an RSA public key of at least 2048 bits.")
    return key


def _identity(claims: dict) -> AuthIdentity:
    if any(type(claims[name]) is not int for name in ("iat", "nbf", "exp")):
        raise ValueError("Invalid timestamp claim.")
    if not isinstance(claims["aud"], list) or not all(
        isinstance(audience, str) for audience in claims["aud"]
    ):
        raise ValueError("Invalid audience claim.")
    if claims["type"] != "access" or claims["is_active"] is not True:
        raise ValueError("Expected an active access token.")
    if not all(
        isinstance(claims[name], str)
        for name in ("sub", "jti", "email", "role", "scope")
    ):
        raise ValueError("Invalid identity claim.")
    if claims["role"] not in AUTH_ROLES:
        raise ValueError("Unsupported role.")
    validate_email(claims["email"])
    UUID(claims["jti"])
    return AuthIdentity(
        id=UUID(claims["sub"]),
        email=claims["email"],
        role=claims["role"],
        scopes=frozenset(claims["scope"].split()),
    )


class AuthJWTAuthentication(BaseAuthentication):
    """Authenticate independently of Gateway headers and Django Admin sessions."""

    def authenticate(self, request):
        header = get_authorization_header(request).split()
        if not header:
            return None
        if len(header) != 2 or header[0].lower() != b"bearer":
            raise AuthenticationFailed("Expected a Bearer access token.")

        try:
            key = _verification_key(
                settings.JWT_PUBLIC_KEY,
                settings.BASE_DIR / settings.JWT_PUBLIC_KEY_PATH,
            )
            claims = jwt.decode(
                header[1],
                key,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCES,
                options={"require": REQUIRED_CLAIMS},
            )
            return _identity(claims), claims
        except (
            jwt.InvalidTokenError,
            UnsupportedAlgorithm,
            ValidationError,
            OSError,
            ValueError,
            TypeError,
            OverflowError,
        ):
            raise AuthenticationFailed("Invalid Bearer access token.") from None

    def authenticate_header(self, request):
        return "Bearer"
