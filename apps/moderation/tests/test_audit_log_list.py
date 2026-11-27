import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlencode
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.moderation.models import ActionType, AuditLog
from apps.moderation.tests.test_audit_log import audit_fields

URL = "/api/v1/moderation/audit-logs/"
ISSUER = "https://auth.conectanexus.ufps.edu.co"
AUDIENCES = ["conecta-nexus-gateway", "conecta-nexus-services"]
MIDNIGHT = datetime(2026, 11, 24, tzinfo=UTC)


def public_pem(key):
    return (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


class AuditLogListTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_signer = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        configuration = override_settings(
            JWT_PUBLIC_KEY=public_pem(cls.signer),
            JWT_ISSUER=ISSUER,
            JWT_AUDIENCES=AUDIENCES,
        )
        configuration.enable()
        cls.addClassCleanup(configuration.disable)

    def setUp(self):
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token()}")

    def claims(self, **changes):
        now = int(datetime.now(UTC).timestamp())
        return {
            "iss": ISSUER,
            "aud": AUDIENCES,
            "sub": str(uuid4()),
            "jti": str(uuid4()),
            "iat": now,
            "nbf": now,
            "exp": now + 900,
            "type": "access",
            "email": "admin@example.org",
            "role": "ADMIN",
            "is_active": True,
            "scope": "challenge:moderate audit:read",
            **changes,
        }

    def token(self, **changes):
        return jwt.encode(self.claims(**changes), self.signer, algorithm="RS256")

    def authorization(self, token):
        return APIClient().get(URL, HTTP_AUTHORIZATION=f"Bearer {token}")

    def expect_unauthorized(self, response):
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["WWW-Authenticate"], "Bearer")
        self.assertIn("detail", response.json())

    def insert(self, number=1, timestamp=MIDNIGHT, **overrides):
        fields = audit_fields(**overrides)
        # Seed historical timestamps by inserting them once, without bypassing immutability.
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO moderation_auditlog (
                    id, actor_id, actor_email, actor_role, action_type, target_id,
                    target_type, justification, ip_address, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                [UUID(int=number), *fields.values(), timestamp],
            )

    def test_audit_log_list_rejects_missing_credentials_and_django_session(self):
        anonymous = APIClient()
        spoofed = {
            "HTTP_X_USER_ROLE": "ADMIN",
            "HTTP_X_USER_SCOPES": "audit:read",
            "HTTP_X_USER_ID": str(uuid4()),
            "HTTP_X_USER_EMAIL": "spoof@example.org",
        }
        self.expect_unauthorized(anonymous.get(URL, **spoofed))
        anonymous.force_login(get_user_model().objects.create_superuser("local-admin"))
        self.expect_unauthorized(anonymous.get(URL))

    def test_audit_log_list_rejects_malformed_headers(self):
        for header in (
            "Basic xyz",
            "Bearer",
            "Bearer  ",
            "Bearer x y",
            "Bearer not-a-jwt",
        ):
            with self.subTest(header=header):
                self.expect_unauthorized(
                    APIClient().get(URL, HTTP_AUTHORIZATION=header)
                )

    def test_audit_log_list_rejects_invalid_signatures_and_algorithms(self):
        claims = self.claims()
        for token in (
            jwt.encode(claims, self.other_signer, algorithm="RS256"),
            jwt.encode(claims, self.signer, algorithm="RS384"),
            jwt.encode(
                claims,
                "synthetic-key-for-tests-only-of-sufficient-length",
                algorithm="HS256",
            ),
            jwt.encode(claims, None, algorithm="none"),
        ):
            self.expect_unauthorized(self.authorization(token))

    def test_audit_log_list_rejects_invalid_claims(self):
        now = int(datetime.now(UTC).timestamp())
        for changes in (
            {"iss": "https://invalid.example.org"},
            {"aud": ["untrusted"]},
            {"aud": AUDIENCES[0]},
            {"aud": [1]},
            {"sub": "invalid"},
            {"sub": 12},
            {"jti": "invalid"},
            {"jti": 12},
            {"email": "invalid"},
            {"email": []},
            {"iat": now + 1000},
            {"iat": None},
            {"iat": str(now)},
            {"nbf": now + 1000},
            {"nbf": True},
            {"exp": now - 1},
            {"exp": float(now + 900)},
            {"type": "refresh"},
            {"type": "password_reset"},
            {"is_active": False},
            {"is_active": 1},
            {"role": "ROOT"},
            {"role": []},
            {"scope": ["audit:read"]},
        ):
            with self.subTest(changes=changes):
                self.expect_unauthorized(self.authorization(self.token(**changes)))

    def test_audit_log_list_requires_every_auth_claim(self):
        claims = self.claims()
        for missing in claims:
            with self.subTest(missing=missing):
                payload = {
                    key: value for key, value in claims.items() if key != missing
                }
                self.expect_unauthorized(
                    self.authorization(
                        jwt.encode(payload, self.signer, algorithm="RS256")
                    )
                )

    def test_audit_log_list_fails_closed_without_trusted_rsa_key(self):
        for pem in (
            "invalid PEM",
            public_pem(self.other_signer),
            public_pem(ec.generate_private_key(ec.SECP256R1())),
            public_pem(rsa.generate_private_key(public_exponent=65537, key_size=1024)),
            "",
        ):
            with (
                self.subTest(key_kind=pem[:10]),
                override_settings(
                    JWT_PUBLIC_KEY=pem, JWT_PUBLIC_KEY_PATH="missing-test-key.pem"
                ),
            ):
                self.expect_unauthorized(self.client.get(URL))

    def test_audit_log_list_uses_configured_public_key_path(self):
        with TemporaryDirectory() as directory:
            key_path = Path(directory) / "auth-public.pem"
            key_path.write_text(public_pem(self.signer), encoding="ascii")
            with override_settings(
                JWT_PUBLIC_KEY="", JWT_PUBLIC_KEY_PATH=str(key_path)
            ):
                self.assertEqual(self.client.get(URL).status_code, 200)

    def test_audit_log_list_requires_admin_and_audit_scope(self):
        for role in ("STUDENT", "COMPANY"):
            with self.subTest(role=role):
                response = APIClient().get(
                    URL,
                    HTTP_AUTHORIZATION=f"Bearer {self.token(role=role)}",
                    HTTP_X_USER_ROLE="ADMIN",
                )
                self.assertEqual(response.status_code, 403)
        for scope in ("challenge:moderate", "audit:read_all", ""):
            with self.subTest(scope=scope):
                self.assertEqual(
                    self.authorization(self.token(scope=scope)).status_code, 403
                )
        self.assertEqual(self.client.get(URL).status_code, 200)

    def test_audit_log_list_matches_all_persisted_fields(self):
        reason = "Line one\n" + "Complete synthetic text " * 100
        self.insert(justification=reason, ip_address="2001:db8::1")
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT to_jsonb(a) || jsonb_build_object('ip_address', host(ip_address))
                FROM moderation_auditlog a WHERE id = %s
                """,
                [UUID(int=1)],
            )
            database_row = json.loads(cursor.fetchone()[0])
        response = self.client.get(URL)
        self.assertEqual(response.status_code, 200)
        expected = {
            **database_row,
            "created_at": MIDNIGHT.isoformat().replace("+00:00", "Z"),
        }
        self.assertEqual(
            response.json(),
            {"count": 1, "next": None, "previous": None, "results": [expected]},
        )

    def test_audit_log_list_default_pages_order_and_ties(self):
        for number in range(1, 47):
            self.insert(number, MIDNIGHT + timedelta(days=number // 2))
        expected = [str(UUID(int=number)) for number in range(46, 0, -1)]
        first = self.client.get(URL).json()
        self.assertEqual(first["count"], 46)
        self.assertIsNone(first["previous"])
        self.assertEqual([row["id"] for row in first["results"]], expected[:20])
        middle = self.client.get(first["next"]).json()
        self.assertEqual([row["id"] for row in middle["results"]], expected[20:40])
        self.assertEqual(
            self.client.get(middle["previous"]).json()["results"], first["results"]
        )
        last = self.client.get(middle["next"]).json()
        self.assertEqual([row["id"] for row in last["results"]], expected[40:])
        self.assertIsNone(last["next"])
        self.assertEqual(self.client.get(URL, {"page": 4}).status_code, 404)

    def test_audit_log_list_filters_dates_actors_and_actions(self):
        actor = uuid4()
        for number, timestamp, action, actor_id in (
            (1, MIDNIGHT - timedelta(microseconds=1), ActionType.CONTENT_FLAG, actor),
            (2, MIDNIGHT, ActionType.CONTENT_FLAG, actor),
            (
                3,
                MIDNIGHT + timedelta(days=1, microseconds=-1),
                ActionType.CONTENT_FLAG,
                actor,
            ),
            (4, MIDNIGHT + timedelta(days=1), ActionType.CONTENT_FLAG, actor),
            (5, MIDNIGHT, ActionType.USER_SUSPEND, actor),
            (6, MIDNIGHT, ActionType.CONTENT_FLAG, uuid4()),
        ):
            self.insert(number, timestamp, action_type=action, actor_id=actor_id)
        for params, expected in (
            ({"action_type": ActionType.USER_SUSPEND}, [5]),
            ({"actor_id": actor}, [4, 3, 5, 2, 1]),
            ({"start_date": "2026-11-24"}, [4, 3, 6, 5, 2]),
            ({"end_date": "2026-11-24"}, [3, 6, 5, 2, 1]),
            ({"start_date": "2026-11-24", "end_date": "2026-11-24"}, [3, 6, 5, 2]),
            (
                {
                    "start_date": "2026-11-24",
                    "end_date": "2026-11-24",
                    "action_type": ActionType.CONTENT_FLAG,
                    "actor_id": actor,
                },
                [3, 2],
            ),
            ({"start_date": "9999-12-31"}, []),
            ({"actor_id": uuid4()}, []),
        ):
            with self.subTest(params=params):
                response = self.client.get(URL, params)
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertEqual(data["count"], len(expected))
                self.assertEqual(
                    [row["id"] for row in data["results"]],
                    [str(UUID(int=n)) for n in expected],
                )

    def test_audit_log_list_links_preserve_filters_with_and_without_admin_mount(self):
        for i in range(1, 4):
            self.insert(i, action_type=ActionType.CONTENT_FLAG)
        query = {
            "action_type": "CONTENT_FLAG",
            "end_date": "2026-11-24",
            "page_size": 1,
        }
        base = f"{URL}?{urlencode(query)}"
        for prefix in ("", "/services/moderation"):
            with (
                self.subTest(prefix=prefix),
                override_settings(FORCE_SCRIPT_NAME=prefix),
            ):
                first = self.client.get(base, SCRIPT_NAME=prefix).json()
                self.assertEqual(first["next"], f"{base}&page=2")
                middle = self.client.get(first["next"], SCRIPT_NAME=prefix).json()
                self.assertEqual(middle["previous"], f"{base}&page=1")
                self.assertEqual(
                    self.client.get(middle["previous"], SCRIPT_NAME=prefix).json(),
                    first,
                )

    def test_audit_log_list_empty_dataset_and_query_validation(self):
        empty = {"count": 0, "next": None, "previous": None, "results": []}
        self.assertEqual(
            self.client.get(URL, {"page_size": 100, "format": "ignored"}).json(), empty
        )
        duplicate = self.client.get(f"{URL}?page=invalid&page=1")
        self.assertEqual(duplicate.status_code, 400)
        self.assertIn("page", duplicate.json())
        for field, values in {
            "page": ("", "last", "1.0", "0", "-2", " 2 "),
            "page_size": ("0", "", "101", "1e2"),
            "action_type": ("", "content_flag", "FAKE"),
            "actor_id": ("", "not-uuid"),
            "start_date": ("2026-2-01", "2026-02-30", "2026-11-24T00:00:00Z"),
            "end_date": ("", "2026/11/24", "9999-12-31"),
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    response = self.client.get(URL, {field: value})
                    self.assertEqual(response.status_code, 400)
                    self.assertIn(field, response.json())
        response = self.client.get(
            URL, {"start_date": "2026-11-25", "end_date": "2026-11-24"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("end_date", response.json())
        self.assertEqual(self.client.get(URL, {"page": 2}).status_code, 404)

    def test_audit_log_list_methods_preserve_the_database(self):
        self.insert()
        before = list(AuditLog.objects.values())
        for method in ("post", "put", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(
                    URL, {"justification": "changed"}, format="json"
                )
                self.assertEqual(response.status_code, 405)
                self.assertEqual(response.headers["Allow"], "GET, HEAD, OPTIONS")
        self.assertEqual(list(AuditLog.objects.values()), before)
        head = self.client.head(URL)
        self.assertEqual(head.status_code, 200)
        self.assertEqual(head.content, b"")
        self.assertEqual(self.client.options(URL).status_code, 200)
