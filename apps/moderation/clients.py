"""Synchronous inter-service HTTP clients for Challenge and Auth moderation."""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

import httpx
from django.conf import settings

logger = logging.getLogger(__name__)


class ModerationClientError(Exception):
    """Base error for downstream moderation synchronization failures."""


class ModerationTargetNotFoundError(ModerationClientError):
    """Raised when the target challenge or user does not exist upstream."""


class ModerationTargetConflictError(ModerationClientError):
    """Raised when the upstream entity cannot transition due to its current state."""


class ModerationUpstreamUnavailableError(ModerationClientError):
    """Raised when an upstream microservice fails, times out, or rejects auth."""


def _build_headers(auth_header: str | None) -> dict[str, str]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header
    return headers


class ChallengeModerationClient:
    """Client to suspend challenges via the Challenge microservice."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.base_url = (
            base_url
            if base_url is not None
            else getattr(settings, "CHALLENGE_SERVICE_URL", "http://challenge:8000")
        ).rstrip("/")
        self.timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else getattr(settings, "SERVICE_TIMEOUT_SECONDS", 5.0)
        )

    def suspend_challenge(
        self,
        challenge_id: UUID | str,
        justification: str,
        auth_header: str | None = None,
    ) -> dict[str, Any]:
        """Suspend a challenge upstream by transitioning it to CANCELLED."""
        url = f"{self.base_url}/api/v1/challenges/{challenge_id}/suspend"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    url,
                    json={"justification": justification},
                    headers=_build_headers(auth_header),
                )
        except httpx.RequestError as exc:
            logger.error("Challenge service request failed during suspension: %s", exc)
            raise ModerationUpstreamUnavailableError(
                "Challenge service is unavailable."
            ) from exc

        if response.status_code == 404:
            raise ModerationTargetNotFoundError("Challenge not found.")
        if response.status_code == 409:
            raise ModerationTargetConflictError(
                "Challenge is already in a terminal state."
            )
        if response.status_code >= 500 or response.status_code in (401, 403):
            raise ModerationUpstreamUnavailableError(
                f"Challenge service rejected suspension (HTTP {response.status_code})."
            )
        if response.status_code >= 400:
            raise ModerationUpstreamUnavailableError(
                f"Challenge service returned HTTP {response.status_code}."
            )
        return response.json()


class AuthModerationClient:
    """Client to deactivate users via the Auth microservice."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.base_url = (
            base_url
            if base_url is not None
            else getattr(settings, "AUTH_SERVICE_URL", "http://auth:8000")
        ).rstrip("/")
        self.timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else getattr(settings, "SERVICE_TIMEOUT_SECONDS", 5.0)
        )

    def suspend_user(
        self,
        user_id: UUID | str,
        auth_header: str | None = None,
    ) -> dict[str, Any]:
        """Deactivate a user account upstream via PATCH /api/v1/auth/users/{id}/status."""
        url = f"{self.base_url}/api/v1/auth/users/{user_id}/status"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.patch(
                    url,
                    json={"is_active": False},
                    headers=_build_headers(auth_header),
                )
        except httpx.RequestError as exc:
            logger.error("Auth service request failed during user suspension: %s", exc)
            raise ModerationUpstreamUnavailableError(
                "Auth service is unavailable."
            ) from exc

        if response.status_code == 404:
            raise ModerationTargetNotFoundError("User not found.")
        if response.status_code >= 500 or response.status_code in (401, 403):
            raise ModerationUpstreamUnavailableError(
                f"Auth service rejected user suspension (HTTP {response.status_code})."
            )
        if response.status_code >= 400:
            raise ModerationUpstreamUnavailableError(
                f"Auth service returned HTTP {response.status_code}."
            )
        return response.json()
