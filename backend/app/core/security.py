
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
JWT_ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
)

password_hasher = PasswordHash.recommended()

bearer_scheme = HTTPBearer(auto_error=False)

ALLOWED_ROLES = {
    "admin",
    "analyst",
    "viewer",
}


# --------------------------------------------------
# SECRET VALIDATION
# --------------------------------------------------

def get_jwt_secret() -> str:
    """
    Return the configured JWT secret.

    A missing secret must not silently generate an
    insecure, predictable default.
    """
    if len(JWT_SECRET_KEY) < 32:
        raise RuntimeError(
            "JWT_SECRET_KEY must be configured with a "
            "strong secret of at least 32 characters."
        )

    return JWT_SECRET_KEY


def generate_secret_key() -> str:
    """Generate a cryptographically secure secret."""
    return secrets.token_urlsafe(48)


# --------------------------------------------------
# PASSWORD HASHING
# --------------------------------------------------

def hash_password(password: str) -> str:
    """Hash a password using the configured password hasher."""
    if not password:
        raise ValueError("Password cannot be empty.")

    return password_hasher.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    """Verify a password against its stored hash."""
    if not plain_password or not hashed_password:
        return False

    try:
        return password_hasher.verify(
            plain_password,
            hashed_password,
        )
    except Exception:
        return False


# --------------------------------------------------
# JWT TOKEN CREATION
# --------------------------------------------------

def create_access_token(
    subject: str,
    role: str = "viewer",
    expires_delta: timedelta | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Create a signed JWT access token.

    The subject should be a stable user identifier,
    not a password or other secret.
    """
    if not subject or not subject.strip():
        raise ValueError("Token subject cannot be empty.")

    normalized_role = role.strip().lower()

    if normalized_role not in ALLOWED_ROLES:
        raise ValueError("Invalid user role.")

    now = datetime.now(timezone.utc)
    expiry = now + (
        expires_delta
        or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    payload: dict[str, Any] = {
        "sub": subject,
        "role": normalized_role,
        "iat": now,
        "exp": expiry,
    }

    if extra_claims:
        # Do not allow callers to override critical claims.
        reserved_claims = {"sub", "role", "iat", "exp"}
        if reserved_claims.intersection(extra_claims):
            raise ValueError(
                "Extra claims cannot override reserved JWT claims."
            )

        payload.update(extra_claims)

    return jwt.encode(
        payload,
        get_jwt_secret(),
        algorithm=JWT_ALGORITHM,
    )


# --------------------------------------------------
# JWT TOKEN VERIFICATION
# --------------------------------------------------

def decode_access_token(token: str) -> dict[str, Any]:
    """Verify a JWT signature and its expiration."""
    try:
        payload = jwt.decode(
            token,
            get_jwt_secret(),
            algorithms=[JWT_ALGORITHM],
            options={
                "require": ["sub", "iat", "exp"],
            },
        )

        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject:
            raise jwt.InvalidTokenError(
                "Invalid token subject."
            )

        role = payload.get("role", "viewer")
        if role not in ALLOWED_ROLES:
            raise jwt.InvalidTokenError(
                "Invalid token role."
            )

        return payload

    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# --------------------------------------------------
# AUTHENTICATION DEPENDENCY
# --------------------------------------------------

def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
) -> dict[str, Any]:
    """
    Validate the Bearer token and return its claims.

    Use this dependency on endpoints requiring login.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return decode_access_token(credentials.credentials)


# --------------------------------------------------
# ROLE-BASED AUTHORIZATION
# --------------------------------------------------

def require_roles(*allowed_roles: str):
    """
    Create a FastAPI dependency that restricts an endpoint
    to the specified roles.

    Example:
        Depends(require_roles("admin", "analyst"))
    """
    normalized_roles = {
        role.strip().lower()
        for role in allowed_roles
    }

    invalid_roles = normalized_roles - ALLOWED_ROLES
    if invalid_roles:
        raise ValueError(
            f"Unsupported roles: {sorted(invalid_roles)}"
        )

    def role_checker(
        current_user: dict[str, Any] = Depends(
            get_current_user
        ),
    ) -> dict[str, Any]:
        if current_user.get("role", "viewer") not in normalized_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource.",
            )

        return current_user

    return role_checker
