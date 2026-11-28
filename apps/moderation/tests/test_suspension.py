from datetime import UTC, datetime
from uuid import uuid4

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.moderation.models import ActionType, AuditLog, ImmutableLogError, TargetType

ISSUER = "https://auth.conectanexus.ufps.edu.co"
AUDIENCES = ["conecta-nexus-gateway", "conecta-nexus-services"]
CHALLENGE_BASE_URL = "http://challenge:8000"
AUTH_BASE_URL = "http://auth:8000"


def _public_pem(key) -> str:
    return (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


class ModerationSuspensionTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        configuration = override_settings(
            JWT_PUBLIC_KEY=_public_pem(cls.signer),
            JWT_ISSUER=ISSUER,
            JWT_AUDIENCES=AUDIENCES,
            CHALLENGE_SERVICE_URL=CHALLENGE_BASE_URL,
            AUTH_SERVICE_URL=AUTH_BASE_URL,
        )
        configuration.enable()
        cls.addClassCleanup(configuration.disable)

    def setUp(self):
        self.client = APIClient()

    def _token(self, **overrides) -> str:
        now = int(datetime.now(UTC).timestamp())
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCES,
            "sub": str(uuid4()),
            "jti": str(uuid4()),
            "iat": now,
            "nbf": now,
            "exp": now + 900,
            "type": "access",
            "email": "moderator@conectanexus.ufps.edu.co",
            "role": "ADMIN",
            "is_active": True,
            "scope": "challenge:moderate user:status:write audit:read",
            **overrides,
        }
        return jwt.encode(claims, self.signer, algorithm="RS256")

    def test_suspension_rejects_non_admin_with_403(self):
        challenge_id = uuid4()
        student_token = self._token(role="STUDENT", scope="challenge:read")
        company_token = self._token(role="COMPANY", scope="challenge:write_own")

        for token in (student_token, company_token):
            resp = self.client.post(
                f"/api/v1/moderation/challenges/{challenge_id}/suspend/",
                {"justification": "Contains prohibited commercial spam content."},
                format="json",
                HTTP_AUTHORIZATION=f"Bearer {token}",
            )
            self.assertEqual(resp.status_code, 403)
        self.assertEqual(AuditLog.objects.count(), 0)

    def test_suspension_rejects_short_justification_with_400(self):
        challenge_id = uuid4()
        admin_token = self._token()
        resp = self.client.post(
            f"/api/v1/moderation/challenges/{challenge_id}/suspend/",
            {"justification": "   too short   "},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {admin_token}",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(AuditLog.objects.count(), 0)

    @respx.mock
    def test_suspension_challenge_success_records_immutable_audit_log(self):
        challenge_id = uuid4()
        admin_token = self._token()
        route = respx.post(
            f"{CHALLENGE_BASE_URL}/api/v1/challenges/{challenge_id}/suspend"
        ).respond(
            200,
            json={"id": str(challenge_id), "status": "CANCELLED"},
        )

        resp = self.client.post(
            f"/api/v1/moderation/challenges/{challenge_id}/suspend/",
            {"justification": "Violates academic project guidelines and Law 1581."},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {admin_token}",
            HTTP_X_FORWARDED_FOR="203.0.113.42, 10.0.0.1",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(route.called)
        data = resp.json()
        self.assertEqual(data["target"]["status"], "CANCELLED")
        self.assertEqual(data["audit_log"]["action_type"], ActionType.CHALLENGE_SUSPEND)
        self.assertEqual(data["audit_log"]["target_type"], TargetType.CHALLENGE)
        self.assertEqual(data["audit_log"]["ip_address"], "203.0.113.42")

        log = AuditLog.objects.get(target_id=challenge_id)
        with pytest.raises(ImmutableLogError):
            log.delete()
        with pytest.raises(ImmutableLogError):
            AuditLog.objects.filter(pk=log.pk).update(justification="tampered")

    @respx.mock
    def test_suspension_challenge_downstream_failure_rolls_back_audit_log(self):
        challenge_id = uuid4()
        admin_token = self._token()
        respx.post(
            f"{CHALLENGE_BASE_URL}/api/v1/challenges/{challenge_id}/suspend"
        ).respond(503, json={"detail": "Service unavailable"})

        resp = self.client.post(
            f"/api/v1/moderation/challenges/{challenge_id}/suspend/",
            {"justification": "Violates academic project guidelines and Law 1581."},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {admin_token}",
        )
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(AuditLog.objects.count(), 0)

    @respx.mock
    def test_suspension_challenge_404_and_409_mapping(self):
        missing_id = uuid4()
        terminal_id = uuid4()
        admin_token = self._token()
        respx.post(
            f"{CHALLENGE_BASE_URL}/api/v1/challenges/{missing_id}/suspend"
        ).respond(404)
        respx.post(
            f"{CHALLENGE_BASE_URL}/api/v1/challenges/{terminal_id}/suspend"
        ).respond(409)

        resp_404 = self.client.post(
            f"/api/v1/moderation/challenges/{missing_id}/suspend/",
            {"justification": "Valid justification over fifteen chars."},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {admin_token}",
        )
        resp_409 = self.client.post(
            f"/api/v1/moderation/challenges/{terminal_id}/suspend/",
            {"justification": "Valid justification over fifteen chars."},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {admin_token}",
        )
        self.assertEqual(resp_404.status_code, 404)
        self.assertEqual(resp_409.status_code, 409)
        self.assertEqual(AuditLog.objects.count(), 0)

    @respx.mock
    def test_suspension_user_success_and_auth_failure_rollback(self):
        user_id = uuid4()
        failed_user_id = uuid4()
        admin_token = self._token()
        respx.patch(f"{AUTH_BASE_URL}/api/v1/auth/users/{user_id}/status").respond(
            200, json={"id": str(user_id), "is_active": False}
        )
        respx.patch(
            f"{AUTH_BASE_URL}/api/v1/auth/users/{failed_user_id}/status"
        ).mock(side_effect=httpx.ConnectError("Connection refused"))

        ok_resp = self.client.post(
            f"/api/v1/moderation/users/{user_id}/suspend/",
            {"justification": "Repeated impersonation of corporate representatives."},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {admin_token}",
        )
        self.assertEqual(ok_resp.status_code, 200)
        self.assertEqual(
            ok_resp.json()["audit_log"]["action_type"], ActionType.USER_SUSPEND
        )
        self.assertEqual(AuditLog.objects.count(), 1)

        err_resp = self.client.post(
            f"/api/v1/moderation/users/{failed_user_id}/suspend/",
            {"justification": "Repeated impersonation of corporate representatives."},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {admin_token}",
        )
        self.assertEqual(err_resp.status_code, 502)
        self.assertEqual(AuditLog.objects.count(), 1)
