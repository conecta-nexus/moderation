import importlib
import io
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from secrets import token_urlsafe
from unittest.mock import patch

from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.staticfiles.handlers import StaticFilesHandler
from django.core.exceptions import ImproperlyConfigured
from django.core.handlers.wsgi import WSGIHandler
from django.db import connection
from django.test import Client, TestCase, override_settings
from django.test.utils import override_script_prefix
from django.urls import clear_url_caches, reverse
from django.utils.html import escape

from apps.moderation.models import AuditLog, ImmutableLogError
from apps.moderation.tests.test_audit_log import audit_fields
from config.settings import parse_csrf_trusted_origins, parse_force_script_name


def insert_at(created_at, **overrides):
    record_id = overrides.pop("id", uuid.uuid4())
    fields = audit_fields(**overrides)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO moderation_auditlog
                (id, actor_id, actor_email, actor_role, action_type, target_id,
                 target_type, justification, ip_address, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            [record_id, *fields.values(), created_at],
        )
    return AuditLog.objects.get(pk=record_id)


@override_settings(
    FORCE_SCRIPT_NAME=None,
    SESSION_COOKIE_PATH="/",
    CSRF_COOKIE_PATH="/",
)
@override_script_prefix("/")
class AuditLogAdminTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        users = get_user_model().objects
        cls.password = token_urlsafe(24)
        cls.staff = users.create_user(
            "audit-reader", password=cls.password, is_staff=True
        )
        cls.staff.user_permissions.add(Permission.objects.get(codename="view_auditlog"))
        cls.no_view = users.create_user("staff-with-change-only", is_staff=True)
        cls.no_view.user_permissions.add(
            Permission.objects.get(codename="change_auditlog")
        )
        cls.inactive = users.create_user(
            "inactive-audit-reader", is_staff=True, is_active=False
        )
        cls.inactive.user_permissions.add(
            Permission.objects.get(codename="view_auditlog")
        )
        cls.non_staff = users.create_user("non-staff-audit-reader")
        cls.non_staff.user_permissions.add(
            Permission.objects.get(codename="view_auditlog")
        )
        cls.superuser = users.create_superuser("audit-superuser", password=cls.password)
        cls.record = insert_at(
            datetime(2026, 11, 19, tzinfo=UTC),
            actor_email="Governance.Reviewer@example.org",
            justification="Inventario institucional <b>texto sin confianza</b>",
            ip_address="2001:db8::5",
        )
        cls.end_of_day = insert_at(
            datetime(2026, 11, 19, 23, 59, 59, 999999, tzinfo=UTC),
            action_type="USER_SUSPEND",
            target_type="USER",
        )
        cls.next_day = insert_at(
            datetime(2026, 11, 20, tzinfo=UTC), action_type="CONTENT_FLAG"
        )
        cls.previous = insert_at(
            datetime(2026, 11, 18, 23, 59, tzinfo=UTC), action_type="CONTENT_FLAG"
        )

    def setUp(self):
        self.changelist = reverse("admin:moderation_auditlog_changelist")
        self.detail = reverse("admin:moderation_auditlog_change", args=[self.record.pk])
        self.add = reverse("admin:moderation_auditlog_add")
        self.delete = reverse("admin:moderation_auditlog_delete", args=[self.record.pk])

    def list_ids(self, params=None):
        response = self.client.get(self.changelist, params or {})
        self.assertEqual(response.status_code, 200)
        return response, [record.pk for record in response.context["cl"].result_list]

    def test_registered_with_consistent_institutional_branding(self):
        self.assertTrue(admin.site.is_registered(AuditLog))
        login = self.client.get(reverse("admin:login"))
        self.assertContains(login, "Conecta Nexus · Administración")
        self.assertContains(login, "moderation/audit-admin.css")
        self.client.force_login(self.staff)
        index = self.client.get(reverse("admin:index"))
        self.assertContains(index, "Administración institucional")
        self.assertContains(index, self.changelist)

    def test_anonymous_nonstaff_and_inactive_sessions_are_denied(self):
        for account in (None, self.non_staff, self.inactive):
            with self.subTest(account=account):
                self.client.logout()
                if account is not None:
                    self.client.force_login(account)
                for url in (self.changelist, self.detail):
                    response = self.client.get(url)
                    self.assertRedirects(
                        response,
                        f"{reverse('admin:login')}?next={url}",
                        fetch_redirect_response=False,
                    )
                    self.assertNotContains(
                        response, self.record.actor_email, status_code=302
                    )

    def test_staff_with_change_permission_but_without_view_permission_is_denied(self):
        self.client.force_login(self.no_view)
        self.assertNotContains(self.client.get(reverse("admin:index")), self.changelist)
        self.assertEqual(self.client.get(self.changelist).status_code, 403)
        self.assertEqual(self.client.get(self.detail).status_code, 403)

    def test_authorized_staff_list_and_see_all_readonly_detail_fields(self):
        self.client.force_login(self.staff)
        listing, ids = self.list_ids()
        self.assertIn(self.record.pk, ids)
        self.assertContains(listing, self.record.get_action_type_display())
        self.assertContains(listing, self.record.get_target_type_display())
        self.assertContains(listing, self.detail)
        detail = self.client.get(self.detail)
        for field in (
            self.record.pk,
            self.record.actor_id,
            self.record.actor_email,
            self.record.actor_role,
            self.record.action_type,
            self.record.target_id,
            self.record.target_type,
            escape(self.record.justification),
            self.record.ip_address,
        ):
            self.assertContains(detail, str(field))
        self.assertContains(detail, 'class="form-row field-created_at"')
        self.assertContains(detail, self.changelist)
        self.assertNotContains(detail, "<b>texto sin confianza</b>")
        self.assertNotContains(detail, 'name="justification"')
        for control in ('name="_save"', 'name="_continue"', "deletelink"):
            self.assertNotContains(detail, control)

    def test_superuser_permissions_and_forged_requests_keep_exact_rows(self):
        self.client.force_login(self.superuser)
        before = list(AuditLog.objects.values())
        response, ids = self.list_ids()
        self.assertIn(self.record.pk, ids)
        self.assertEqual(self.client.get(self.detail).status_code, 200)
        self.assertNotContains(response, self.add)
        self.assertNotContains(response, 'name="action"')
        model_admin = admin.site.get_model_admin(AuditLog)
        request = response.wsgi_request
        self.assertTrue(model_admin.has_view_permission(request, self.record))
        self.assertFalse(model_admin.has_add_permission(request))
        self.assertFalse(model_admin.has_change_permission(request, self.record))
        self.assertFalse(model_admin.has_delete_permission(request, self.record))
        self.assertEqual(model_admin.get_actions(request), {})

        for method, url, data in (
            ("get", self.add, {}),
            ("post", self.add, {"justification": "forged"}),
            ("post", self.detail, {"justification": "forged", "_save": "Save"}),
            ("get", self.delete, {}),
            ("post", self.delete, {"post": "yes"}),
            (
                "post",
                self.changelist,
                {
                    "action": "delete_selected",
                    "_selected_action": [str(self.record.pk)],
                },
            ),
            ("post", self.changelist, {}),
        ):
            with self.subTest(method=method, url=url, data=data):
                rejected = getattr(self.client, method)(url, data)
                self.assertEqual(rejected.status_code, 403)
                self.assertEqual(list(AuditLog.objects.values()), before)
        with self.assertRaises(ImmutableLogError):
            AuditLog.objects.filter(pk=self.record.pk).update(justification="Rejected")
        AuditLog.objects.create(**audit_fields())
        self.assertEqual(AuditLog.objects.count(), len(before) + 1)

    def test_native_login_csrf_and_logout_are_enforced(self):
        client = Client(enforce_csrf_checks=True)
        login_url = reverse("admin:login")
        client.get(login_url)
        credentials = {"username": self.staff.username, "password": self.password}
        self.assertEqual(client.post(login_url, credentials).status_code, 403)
        csrf = client.cookies[settings.CSRF_COOKIE_NAME].value
        self.assertEqual(
            client.post(login_url, credentials, HTTP_X_CSRFTOKEN=csrf).status_code, 302
        )
        self.assertEqual(client.get(self.changelist).status_code, 200)
        csrf = client.cookies[settings.CSRF_COOKIE_NAME].value
        self.assertEqual(
            client.post(self.detail, {}, HTTP_X_CSRFTOKEN=csrf).status_code, 403
        )
        self.assertEqual(
            client.post(reverse("admin:logout"), HTTP_X_CSRFTOKEN=csrf).status_code, 200
        )
        self.assertEqual(client.get(self.detail).status_code, 302)

    def test_search_by_email_exact_uuid_and_reason(self):
        self.client.force_login(self.staff)
        for term in (
            "REVIEWER@EXAMPLE",
            str(self.record.target_id),
            "INVENTARIO institucional",
        ):
            with self.subTest(term=term):
                _, ids = self.list_ids({"q": term})
                self.assertEqual(ids, [self.record.pk])
        for term in (
            "a1b2-invalid-uuid",
            str(uuid.uuid4()),
            str(self.record.target_id)[:9],
        ):
            with self.subTest(term=term):
                self.assertEqual(self.list_ids({"q": term})[1], [])
        self.assertEqual(len(self.list_ids({"q": "   "})[1]), 4)

    def test_action_and_target_filters_are_independent_and_composable(self):
        self.client.force_login(self.staff)
        self.assertEqual(
            self.list_ids({"action_type__exact": "USER_SUSPEND"})[1],
            [self.end_of_day.pk],
        )
        self.assertEqual(
            self.list_ids({"target_type__exact": "USER"})[1], [self.end_of_day.pk]
        )
        self.assertEqual(
            self.list_ids(
                {"action_type__exact": "CONTENT_FLAG", "target_type__exact": "USER"}
            )[1],
            [],
        )
        self.assertEqual(
            self.list_ids(
                {
                    "q": "inventario",
                    "action_type__exact": "CHALLENGE_SUSPEND",
                    "target_type__exact": "CHALLENGE",
                    "start_date": "2026-11-19",
                    "end_date": "2026-11-19",
                }
            )[1],
            [self.record.pk],
        )

    def test_date_filter_range_includes_both_clock_boundaries_and_supports_clear(self):
        self.client.force_login(self.staff)
        cases = (
            (
                {"start_date": "2026-11-19", "end_date": "2026-11-19"},
                [self.end_of_day.pk, self.record.pk],
            ),
            (
                {"start_date": "2026-11-19"},
                [self.next_day.pk, self.end_of_day.pk, self.record.pk],
            ),
            (
                {"end_date": "2026-11-19"},
                [self.end_of_day.pk, self.record.pk, self.previous.pk],
            ),
            (
                {"start_date": "", "end_date": ""},
                [
                    self.next_day.pk,
                    self.end_of_day.pk,
                    self.record.pk,
                    self.previous.pk,
                ],
            ),
        )
        for params, expected in cases:
            with self.subTest(params=params):
                response, ids = self.list_ids(params)
                self.assertEqual(ids, expected)
                self.assertContains(response, "Aplicar fechas")
        response, _ = self.list_ids({"q": "inventario", "end_date": "2026-11-19"})
        self.assertContains(response, 'href="?q=inventario"')
        self.assertContains(response, 'name="q" value="inventario"')

    def test_invalid_and_reversed_dates_report_errors_and_return_no_records(self):
        self.client.force_login(self.staff)
        for params, message in (
            ({"start_date": "2026-02-30"}, "Ingresa una fecha válida."),
            (
                {"start_date": "2026-11-20", "end_date": "2026-11-19"},
                "anterior o igual",
            ),
            ({"end_date": "9999-12-31"}, "Selecciona una fecha anterior"),
        ):
            with self.subTest(params=params):
                response, ids = self.list_ids(params)
                self.assertEqual(ids, [])
                self.assertContains(response, message)

    def test_deterministic_order_and_pagination_keep_search_and_filter(self):
        self.client.force_login(self.staff)
        same_time = datetime(2026, 11, 23, tzinfo=UTC)
        ids = [uuid.UUID(int=number) for number in range(1, 24)]
        for record_id in ids:
            insert_at(same_time, id=record_id, justification="Pagination fixture")
        params = {"q": "pagination fixture", "start_date": "2026-11-23"}
        _, first = self.list_ids(params)
        _, second = self.list_ids({**params, "p": 2})
        self.assertEqual(first, list(reversed(ids))[:20])
        self.assertEqual(second, list(reversed(ids))[20:])


class GatewayMountConfigurationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        users = get_user_model().objects
        cls.password = token_urlsafe(24)
        cls.staff = users.create_user(
            "gateway-audit-reader", password=cls.password, is_staff=True
        )
        cls.staff.user_permissions.add(Permission.objects.get(codename="view_auditlog"))
        cls.superuser = users.create_superuser(
            "gateway-audit-superuser", password=cls.password
        )
        cls.record = insert_at(
            datetime(2026, 11, 19, tzinfo=UTC),
            actor_email="Gateway.Reviewer@example.org",
            justification="Inventario puerta de enlace",
            ip_address="192.0.2.80",
        )

    def _wsgi_get(self, handler, path_info, host="localhost"):
        captured = {}

        def start_response(status, headers, exc_info=None):
            captured["status"] = int(status.split(" ", 1)[0])
            captured["headers"] = dict(headers)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path_info,
            "QUERY_STRING": "",
            "SERVER_NAME": host,
            "SERVER_PORT": "80",
            "HTTP_HOST": host,
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "http",
            "wsgi.input": io.BytesIO(b""),
            "wsgi.errors": io.StringIO(),
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
        }
        chunks = b"".join(handler(environ, start_response))
        return captured["status"], captured["headers"], chunks

    def test_default_unmounted_configuration_and_trailing_slash_normalization(self):
        for empty in (None, "", "   ", "/"):
            self.assertIsNone(parse_force_script_name(empty))
        self.assertEqual(
            parse_force_script_name("/services/moderation"), "/services/moderation"
        )
        self.assertEqual(
            parse_force_script_name("/services/moderation/"), "/services/moderation"
        )
        self.assertEqual(parse_csrf_trusted_origins([]), [])
        self.assertEqual(parse_csrf_trusted_origins(["", "   "]), [])
        self.assertEqual(
            parse_csrf_trusted_origins(
                ["http://localhost:8080", "http://localhost:8080", "https://gw.test"]
            ),
            ["http://localhost:8080", "https://gw.test"],
        )
        with (
            override_settings(
                FORCE_SCRIPT_NAME=None,
                CSRF_TRUSTED_ORIGINS=[],
                SESSION_COOKIE_PATH="/",
                CSRF_COOKIE_PATH="/",
                STATIC_URL="static/",
            ),
            override_script_prefix("/"),
        ):
            self.assertIsNone(settings.FORCE_SCRIPT_NAME)
            self.assertEqual(settings.CSRF_TRUSTED_ORIGINS, [])
            self.assertEqual(settings.STATIC_URL, "/static/")
            self.assertEqual(settings.SESSION_COOKIE_PATH, "/")
            self.assertEqual(settings.CSRF_COOKIE_PATH, "/")
            self.assertEqual(reverse("admin:index"), "/admin/")

        clean_env = os.environ.copy()
        clean_env.pop("FORCE_SCRIPT_NAME", None)
        clean_env.pop("CSRF_TRUSTED_ORIGINS", None)
        clean_env.pop("DEBUG", None)
        clean_env["SECRET_KEY"] = "test-only-ephemeral-secret"
        with patch("environ.Env.read_env"):
            pass
        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import environ; environ.Env.read_env = lambda *a, **kw: None; "
                    "import django; django.setup(); from django.conf import settings; "
                    "print(settings.FORCE_SCRIPT_NAME, settings.CSRF_TRUSTED_ORIGINS, "
                    "settings.STATIC_URL, settings.SESSION_COOKIE_SECURE, "
                    "settings.CSRF_COOKIE_SECURE, settings.SESSION_COOKIE_PATH)"
                ),
            ],
            env={**clean_env, "DJANGO_SETTINGS_MODULE": "config.settings"},
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(
            probe.stdout.strip(),
            "None [] /static/ True True /",
        )

    def test_invalid_prefix_and_origin_configurations_raise_improperly_configured(self):
        for bad_prefix in (
            "services/moderation",
            "//evil.example/moderation",
            "/services//moderation",
            "https://example.com/services/moderation",
            "/services/moderation?next=1",
            "/services/moderation#fragment",
            "/services/../admin",
            "/services/./admin",
            "/services/ moderation",
            "/services/\nmoderation",
        ):
            with (
                self.subTest(prefix=bad_prefix),
                self.assertRaises(ImproperlyConfigured),
            ):
                parse_force_script_name(bad_prefix)

        for bad_origin in (
            "*",
            "http://*",
            "https://*.example.com",
            "localhost:8080",
            "ftp://localhost:8080",
            "http://localhost:8080/services/moderation",
            "http://localhost:8080?x=1",
            "http://localhost:8080#top",
            "http://user:pass@localhost:8080",
        ):
            with (
                self.subTest(origin=bad_origin),
                self.assertRaises(ImproperlyConfigured),
            ):
                parse_csrf_trusted_origins([bad_origin])

    @override_settings(
        FORCE_SCRIPT_NAME="/services/moderation",
        SESSION_COOKIE_PATH="/services/moderation/",
        CSRF_COOKIE_PATH="/services/moderation/",
        ALLOWED_HOSTS=["localhost", "testserver"],
        STATIC_URL="static/",
    )
    @override_script_prefix("/services/moderation")
    def test_mounted_prefix_url_generation_redirects_and_admin_navigation(self):
        prefix = "/services/moderation"
        self.assertEqual(settings.STATIC_URL, f"{prefix}/static/")
        self.assertEqual(reverse("admin:index"), f"{prefix}/admin/")
        self.assertEqual(reverse("admin:login"), f"{prefix}/admin/login/")
        self.assertEqual(reverse("admin:logout"), f"{prefix}/admin/logout/")
        self.assertEqual(
            reverse("admin:password_change"), f"{prefix}/admin/password_change/"
        )
        changelist_url = reverse("admin:moderation_auditlog_changelist")
        detail_url = reverse("admin:moderation_auditlog_change", args=[self.record.pk])
        self.assertEqual(changelist_url, f"{prefix}/admin/moderation/auditlog/")
        self.assertEqual(
            detail_url, f"{prefix}/admin/moderation/auditlog/{self.record.pk}/change/"
        )

        for stripped, expected_next in (
            ("/admin/", f"{prefix}/admin/"),
            ("/admin/moderation/auditlog/", changelist_url),
            (
                f"/admin/moderation/auditlog/{self.record.pk}/change/",
                detail_url,
            ),
        ):
            response = self.client.get(stripped)
            self.assertRedirects(
                response,
                f"{prefix}/admin/login/?next={expected_next}",
                fetch_redirect_response=False,
            )

        login_plain = self.client.get("/admin/login/")
        self.assertEqual(login_plain.status_code, 200)
        self.assertContains(login_plain, f'<form action="{prefix}/admin/login/"')
        self.assertContains(login_plain, f'name="next" value="{prefix}/admin/"')

        login = self.client.get("/admin/login/", {"next": changelist_url})
        self.assertEqual(login.status_code, 200)
        self.assertContains(
            login,
            f'<form action="{prefix}/admin/login/?next=%2Fservices%2Fmoderation%2Fadmin%2Fmoderation%2Fauditlog%2F"',
        )
        self.assertContains(login, f'name="next" value="{changelist_url}"')
        self.assertContains(login, f"{prefix}/static/moderation/audit-admin.css")
        self.assertContains(login, f"{prefix}/static/admin/css/login.css")
        self.assertContains(login, f"{prefix}/static/admin/css/base.css")

        self.client.force_login(self.staff)
        index = self.client.get("/admin/")
        self.assertEqual(index.status_code, 200)
        self.assertContains(index, f'href="{prefix}/admin/"')
        self.assertContains(index, f'href="{changelist_url}"')
        self.assertContains(index, f'action="{prefix}/admin/logout/"')
        self.assertContains(index, f'href="{prefix}/admin/password_change/"')

        same_time = datetime(2026, 11, 24, tzinfo=UTC)
        for number in range(21):
            insert_at(
                same_time,
                id=uuid.UUID(int=1000 + number),
                justification="Mounted pagination fixture",
            )
        changelist = self.client.get(
            "/admin/moderation/auditlog/",
            {"q": "inventario", "end_date": "2026-11-19"},
        )
        self.assertEqual(changelist.status_code, 200)
        self.assertContains(changelist, f'href="{detail_url}?_changelist_filters=')
        self.assertContains(changelist, 'id="changelist-search"')
        self.assertContains(changelist, 'href="?q=inventario"')
        self.assertContains(changelist, f"{prefix}/static/moderation/audit-admin.css")
        self.assertContains(changelist, f"{prefix}/static/admin/js/theme.js")

        paginated = self.client.get("/admin/moderation/auditlog/")
        self.assertContains(
            paginated,
            f'href="{prefix}/admin/moderation/auditlog/{uuid.UUID(int=1020)}/change/"',
        )
        self.assertContains(paginated, 'href="?p=2"')
        self.assertContains(paginated, "?action_type__exact=CHALLENGE_SUSPEND")
        page_two = self.client.get("/admin/moderation/auditlog/", {"p": 2})
        self.assertContains(page_two, f'href="{detail_url}?_changelist_filters=p%3D2"')

        detail = self.client.get(f"/admin/moderation/auditlog/{self.record.pk}/change/")
        self.assertEqual(detail.status_code, 200)
        self.assertContains(detail, f'href="{changelist_url}"')

    @override_settings(
        FORCE_SCRIPT_NAME="/services/moderation",
        CSRF_TRUSTED_ORIGINS=["http://localhost:8080"],
        SESSION_COOKIE_PATH="/services/moderation/",
        CSRF_COOKIE_PATH="/services/moderation/",
        ALLOWED_HOSTS=["localhost", "testserver"],
    )
    @override_script_prefix("/services/moderation")
    def test_mounted_csrf_origin_session_logout_and_readonly_enforcement(self):
        client = Client(enforce_csrf_checks=True)
        login_get = client.get("/admin/login/", HTTP_HOST="localhost")
        self.assertEqual(login_get.status_code, 200)
        csrf_token = client.cookies[settings.CSRF_COOKIE_NAME].value
        self.assertEqual(
            client.cookies[settings.CSRF_COOKIE_NAME]["path"], "/services/moderation/"
        )

        # Missing CSRF token -> 403
        self.assertEqual(
            client.post(
                "/admin/login/",
                {"username": self.superuser.username, "password": self.password},
                HTTP_HOST="localhost",
                HTTP_ORIGIN="http://localhost:8080",
            ).status_code,
            403,
        )
        # Invalid CSRF token -> 403
        self.assertEqual(
            client.post(
                "/admin/login/",
                {
                    "username": self.superuser.username,
                    "password": self.password,
                    "csrfmiddlewaretoken": "invalid-csrf-token",
                },
                HTTP_HOST="localhost",
                HTTP_ORIGIN="http://localhost:8080",
            ).status_code,
            403,
        )
        # Untrusted Origin -> 403
        for bad_origin in ("http://evil.example", "http://localhost:9999"):
            with self.subTest(bad_origin=bad_origin):
                self.assertEqual(
                    client.post(
                        "/admin/login/",
                        {
                            "username": self.superuser.username,
                            "password": self.password,
                            "csrfmiddlewaretoken": csrf_token,
                        },
                        HTTP_HOST="localhost",
                        HTTP_ORIGIN=bad_origin,
                    ).status_code,
                    403,
                )

        # Valid CSRF token + trusted Gateway origin -> 302 login success
        login_post = client.post(
            "/admin/login/",
            {
                "username": self.superuser.username,
                "password": self.password,
                "next": "/services/moderation/admin/",
                "csrfmiddlewaretoken": csrf_token,
            },
            HTTP_HOST="localhost",
            HTTP_ORIGIN="http://localhost:8080",
        )
        self.assertRedirects(
            login_post, "/services/moderation/admin/", fetch_redirect_response=False
        )
        session_cookie = client.cookies[settings.SESSION_COOKIE_NAME]
        self.assertEqual(session_cookie["path"], "/services/moderation/")
        self.assertTrue(session_cookie["httponly"])
        self.assertEqual(session_cookie["samesite"], "Lax")

        # Read-only changelist & detail work; mutations remain 403 and preserve rows
        before = list(AuditLog.objects.values())
        self.assertEqual(
            client.get(
                "/admin/moderation/auditlog/", HTTP_HOST="localhost"
            ).status_code,
            200,
        )
        detail_stripped = f"/admin/moderation/auditlog/{self.record.pk}/change/"
        self.assertEqual(
            client.get(detail_stripped, HTTP_HOST="localhost").status_code, 200
        )
        csrf_token = client.cookies[settings.CSRF_COOKIE_NAME].value
        for method, path, data in (
            ("get", "/admin/moderation/auditlog/add/", {}),
            ("post", "/admin/moderation/auditlog/add/", {"justification": "forged"}),
            ("post", detail_stripped, {"justification": "forged", "_save": "Save"}),
            ("get", f"/admin/moderation/auditlog/{self.record.pk}/delete/", {}),
            (
                "post",
                f"/admin/moderation/auditlog/{self.record.pk}/delete/",
                {"post": "yes"},
            ),
            (
                "post",
                "/admin/moderation/auditlog/",
                {
                    "action": "delete_selected",
                    "_selected_action": [str(self.record.pk)],
                },
            ),
        ):
            with self.subTest(method=method, path=path):
                resp = getattr(client, method)(
                    path,
                    data,
                    HTTP_HOST="localhost",
                    HTTP_ORIGIN="http://localhost:8080",
                    HTTP_X_CSRFTOKEN=csrf_token,
                )
                self.assertEqual(resp.status_code, 403)
                self.assertEqual(list(AuditLog.objects.values()), before)

        # Logout succeeds and subsequent detail access redirects to prefixed login
        logout_resp = client.post(
            "/admin/logout/",
            {"csrfmiddlewaretoken": csrf_token},
            HTTP_HOST="localhost",
            HTTP_ORIGIN="http://localhost:8080",
        )
        self.assertEqual(logout_resp.status_code, 200)
        self.assertContains(logout_resp, 'href="/services/moderation/admin/"')
        after_logout = client.get(detail_stripped, HTTP_HOST="localhost")
        self.assertRedirects(
            after_logout,
            f"/services/moderation/admin/login/?next=/services/moderation{detail_stripped}",
            fetch_redirect_response=False,
        )

    @override_settings(
        FORCE_SCRIPT_NAME="/services/moderation",
        CSRF_TRUSTED_ORIGINS=[],
        ALLOWED_HOSTS=["localhost", "testserver"],
    )
    @override_script_prefix("/services/moderation")
    def test_empty_csrf_trusted_origins_rejects_gateway_port_origin(self):
        client = Client(enforce_csrf_checks=True)
        client.get("/admin/login/", HTTP_HOST="localhost")
        csrf_token = client.cookies[settings.CSRF_COOKIE_NAME].value
        rejected = client.post(
            "/admin/login/",
            {
                "username": self.superuser.username,
                "password": self.password,
                "csrfmiddlewaretoken": csrf_token,
            },
            HTTP_HOST="localhost",
            HTTP_ORIGIN="http://localhost:8080",
        )
        self.assertEqual(rejected.status_code, 403)

    def test_static_delivery_and_core_routes_under_mounted_wsgi_handler(self):
        import config.urls as project_urls

        with (
            override_settings(
                DEBUG=True,
                FORCE_SCRIPT_NAME="/services/moderation",
                ALLOWED_HOSTS=["localhost", "testserver"],
                STATIC_URL="static/",
            ),
            override_script_prefix("/services/moderation"),
        ):
            clear_url_caches()
            importlib.reload(project_urls)
            try:
                handler = StaticFilesHandler(WSGIHandler())
                for asset, snippet in (
                    ("/static/moderation/audit-admin.css", b"--audit-brand"),
                    ("/static/admin/css/base.css", b"body"),
                    ("/static/admin/js/theme.js", b"theme"),
                ):
                    status, headers, body = self._wsgi_get(handler, asset)
                    self.assertEqual(status, 200, asset)
                    self.assertIn(snippet, body)
                    self.assertTrue(headers.get("Content-Type"))

                for core_path, expected_key in (
                    ("/", b'"service": "moderation"'),
                    ("/health/", b'"status": "healthy"'),
                ):
                    status, _, body = self._wsgi_get(handler, core_path)
                    self.assertEqual(status, 200)
                    self.assertIn(expected_key, body)
            finally:
                clear_url_caches()
                importlib.reload(project_urls)

        with (
            override_settings(
                DEBUG=False,
                FORCE_SCRIPT_NAME="/services/moderation",
                ALLOWED_HOSTS=["localhost", "testserver"],
                STATIC_URL="static/",
            ),
            override_script_prefix("/services/moderation"),
        ):
            clear_url_caches()
            importlib.reload(project_urls)
            try:
                prod_handler = WSGIHandler()
                status, _, _ = self._wsgi_get(
                    prod_handler, "/static/moderation/audit-admin.css"
                )
                self.assertEqual(status, 404)
            finally:
                clear_url_caches()
                importlib.reload(project_urls)
