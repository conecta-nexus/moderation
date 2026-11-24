import uuid

from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase

from apps.moderation.models import AuditLog
from apps.moderation.tests.test_audit_log import audit_fields

TABLE = "moderation_auditlog"
INITIAL = ("moderation", "0001_initial")
COLUMNS = (
    "id",
    "actor_id",
    "actor_email",
    "actor_role",
    "action_type",
    "target_id",
    "target_type",
    "justification",
    "ip_address",
    "created_at",
)


class AuditLogPostgreSQLTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.record = AuditLog.objects.create(**audit_fields())

    def read_rows(self):
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM {TABLE} ORDER BY id")
            return cursor.fetchall()

    def assert_sql_rejected(self, statement, params, sqlstate, constraint=None):
        original = self.read_rows()
        with (
            self.assertRaises(DatabaseError) as rejected,
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute(statement, params)
        failure = rejected.exception.__cause__
        self.assertEqual(failure.sqlstate, sqlstate)
        if constraint is not None:
            self.assertEqual(failure.diag.constraint_name, constraint)
        else:
            self.assertIn("append-only", failure.diag.message_primary)
        self.assertEqual(self.read_rows(), original)

    def test_direct_update_is_rejected(self):
        self.assert_sql_rejected(
            f"UPDATE {TABLE} SET justification = %s WHERE id = %s",
            ["Attempted change", self.record.pk],
            "55000",
        )

    def test_direct_delete_is_rejected(self):
        self.assert_sql_rejected(
            f"DELETE FROM {TABLE} WHERE id = %s", [self.record.pk], "55000"
        )

    def test_truncate_is_rejected(self):
        self.assert_sql_rejected(f"TRUNCATE {TABLE}", [], "55000")

    def test_on_conflict_update_is_rejected(self):
        self.assert_sql_rejected(
            f"""INSERT INTO {TABLE} ({", ".join(COLUMNS)})
                SELECT {", ".join(COLUMNS)} FROM {TABLE} WHERE id = %s
                ON CONFLICT (id) DO UPDATE SET justification = EXCLUDED.justification""",
            [self.record.pk],
            "55000",
        )

    def test_database_check_constraints_reject_invalid_raw_inserts(self):
        for column, value, constraint in (
            ("justification", "", "audit_justification_nonblank"),
            (
                "justification",
                "\t\n\r \xa0\u2003\u202f",
                "audit_justification_nonblank",
            ),
            ("actor_email", "\t ", "audit_actor_email_nonblank"),
            ("actor_role", "USER", "audit_actor_admin"),
            ("action_type", "INVALID", "audit_action_valid"),
            ("target_type", "INVALID", "audit_target_valid"),
        ):
            fields = audit_fields(**{column: value})
            with self.subTest(column=column, value=value):
                self.assert_sql_rejected(
                    f"""INSERT INTO {TABLE} ({", ".join(COLUMNS[:-1])})
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    [uuid.uuid4(), *fields.values()],
                    "23514",
                    constraint,
                )

    def test_direct_insert_keeps_database_timestamp_default_and_native_ip(self):
        fields = audit_fields(ip_address="2001:db8::3")
        with connection.cursor() as cursor:
            cursor.execute(
                f"""INSERT INTO {TABLE} ({", ".join(COLUMNS[:-1])})
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id, created_at, host(ip_address)""",
                [uuid.uuid4(), *fields.values()],
            )
            identifier, created_at, ip_address = cursor.fetchone()
        self.assertIsNotNone(created_at.utcoffset())
        self.assertEqual(ip_address, fields["ip_address"])
        self.assertEqual(
            AuditLog.objects.get(pk=identifier).actor_id, fields["actor_id"]
        )

    def test_schema_uses_postgresql_types_and_table_primary_key(self):
        self.assertEqual(connection.vendor, "postgresql")
        self.assertGreaterEqual(connection.pg_version, 160000)
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = current_schema() AND table_name = %s
                """,
                [TABLE],
            )
            columns = {
                name: (type_, nullable) for name, type_, nullable in cursor.fetchall()
            }
            constraints = connection.introspection.get_constraints(cursor, TABLE)
        self.assertEqual(set(columns), set(COLUMNS))
        self.assertTrue(all(nullable == "NO" for _, nullable in columns.values()))
        for field in ("id", "actor_id", "target_id"):
            self.assertEqual(columns[field][0], "uuid")
        self.assertEqual(columns["created_at"][0], "timestamp with time zone")
        self.assertEqual(columns["ip_address"][0], "inet")
        self.assertEqual(constraints["moderation_auditlog_pkey"]["columns"], ["id"])
        self.assertTrue(constraints["moderation_auditlog_pkey"]["primary_key"])

    def test_reverse_migration_refuses_to_discard_populated_history(self):
        original = self.read_rows()
        with self.assertRaises(DatabaseError) as rejected, transaction.atomic():
            MigrationExecutor(connection).migrate([("moderation", None)])
        self.assertEqual(rejected.exception.__cause__.sqlstate, "55000")
        self.assertIn(
            "populated audit log", rejected.exception.__cause__.diag.message_primary
        )
        self.assertIn(INITIAL, MigrationExecutor(connection).loader.applied_migrations)
        self.assertEqual(self.read_rows(), original)
        self.assert_sql_rejected(f"TRUNCATE {TABLE}", [], "55000")


class AuditLogMigrationTests(TestCase):
    def test_empty_migration_reverses_and_reapplies_with_protection(self):
        MigrationExecutor(connection).migrate([("moderation", None)])
        self.assertNotIn(TABLE, connection.introspection.table_names())
        MigrationExecutor(connection).migrate([INITIAL])
        self.assertIn(TABLE, connection.introspection.table_names())
        self.assertIn(INITIAL, MigrationExecutor(connection).loader.applied_migrations)
        saved = AuditLog.objects.create(**audit_fields())
        with (
            self.assertRaises(DatabaseError) as rejected,
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute(f"TRUNCATE {TABLE}")
        self.assertEqual(rejected.exception.__cause__.sqlstate, "55000")
        self.assertTrue(AuditLog.objects.filter(pk=saved.pk).exists())
