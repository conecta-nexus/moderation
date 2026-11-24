import uuid

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.moderation.models import (
    ActionType,
    ActorRole,
    AuditLog,
    ImmutableLogError,
    TargetType,
)


def audit_fields(**overrides):
    return {
        "actor_id": uuid.uuid4(),
        "actor_email": "auditor@example.org",
        "actor_role": ActorRole.ADMIN,
        "action_type": ActionType.CHALLENGE_SUSPEND,
        "target_id": uuid.uuid4(),
        "target_type": TargetType.CHALLENGE,
        "justification": "Synthetic moderation review",
        "ip_address": "192.0.2.10",
        **overrides,
    }


class AuditLogValidationTests(TestCase):
    def test_creates_and_reads_a_complete_record_with_generated_identity_and_time(self):
        fields = audit_fields()
        before = timezone.now()
        created = AuditLog.objects.create(**fields)
        saved = AuditLog.objects.get(pk=created.pk)
        self.assertIsInstance(saved.pk, uuid.UUID)
        self.assertNotEqual(saved.pk, AuditLog.objects.create(**fields).pk)
        self.assertTrue(timezone.is_aware(saved.created_at))
        self.assertLessEqual(before, saved.created_at)
        self.assertLessEqual(saved.created_at, timezone.now())
        for field, value in fields.items():
            self.assertEqual(getattr(saved, field), value)

    def test_all_enum_values_and_both_ip_versions_are_accepted(self):
        for action, target, ip in (
            (ActionType.CHALLENGE_SUSPEND, TargetType.CHALLENGE, "192.0.2.10"),
            (ActionType.USER_SUSPEND, TargetType.USER, "2001:db8::1"),
            (ActionType.CONTENT_FLAG, TargetType.USER, "2001:db8::2"),
        ):
            with self.subTest(action=action, target=target, ip=ip):
                saved = AuditLog.objects.create(
                    **audit_fields(
                        action_type=action, target_type=target, ip_address=ip
                    )
                )
                saved.refresh_from_db()
                self.assertEqual(
                    (saved.action_type, saved.target_type, saved.ip_address),
                    (action, target, ip),
                )

    def test_invalid_values_are_rejected_by_single_and_bulk_insert(self):
        for field, value in (
            ("actor_id", None),
            ("actor_id", "invalid"),
            ("actor_email", ""),
            ("actor_email", "invalid"),
            ("actor_role", "USER"),
            ("action_type", "INVALID"),
            ("target_type", "INVALID"),
            ("target_id", None),
            ("target_id", "invalid"),
            ("justification", None),
            ("justification", ""),
            ("justification", "\t\n\r \xa0\u2003\u202f"),
            ("ip_address", None),
            ("ip_address", ""),
            ("ip_address", "2001:db8:::1"),
        ):
            fields = audit_fields(**{field: value})
            with self.subTest(field=field, value=value):
                for bulk in (False, True):
                    with self.assertRaises(ValidationError) as rejected:
                        if bulk:
                            AuditLog.objects.bulk_create([AuditLog(**fields)])
                        else:
                            AuditLog.objects.create(**fields)
                    self.assertIn(field, rejected.exception.message_dict)
        self.assertFalse(AuditLog.objects.exists())

    def test_justification_has_no_future_suspension_minimum(self):
        record = AuditLog.objects.create(**audit_fields(justification="x"))
        self.assertEqual(AuditLog.objects.get(pk=record.pk).justification, "x")

    def test_bulk_insert_validates_before_writing_any_rows(self):
        first = AuditLog(**audit_fields())
        invalid = AuditLog(**audit_fields(ip_address="garbage"))
        with self.assertRaises(ValidationError) as rejected:
            AuditLog.objects.bulk_create([first, invalid], batch_size=1)
        self.assertIn("ip_address", rejected.exception.message_dict)
        self.assertFalse(AuditLog.objects.exists())


class AuditLogImmutabilityTests(TestCase):
    def setUp(self):
        self.record = AuditLog.objects.create(**audit_fields())
        self.original = AuditLog.objects.values().get(pk=self.record.pk)

    def assert_record_unchanged(self):
        self.assertEqual(
            AuditLog.objects.values().get(pk=self.original["id"]), self.original
        )

    def test_persisted_instance_save_and_delete_rejected(self):
        self.record.justification = "Attempted change"
        with self.assertRaisesRegex(ImmutableLogError, "only be inserted once"):
            self.record.save()
        with self.assertRaisesRegex(ImmutableLogError, "cannot be deleted"):
            self.record.delete()
        self.assert_record_unchanged()

    def test_save_flags_and_modified_instance_state_cannot_bypass_guard(self):
        for kwargs in (
            {"force_insert": True},
            {"force_update": True},
            {"update_fields": ["justification"]},
            {"update_fields": []},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ImmutableLogError):
                self.record.save(**kwargs)
        loaded = AuditLog.objects.get(pk=self.record.pk)
        loaded._state.adding = True
        loaded.pk = uuid.uuid4()
        with self.assertRaisesRegex(ImmutableLogError, "only be inserted once"):
            loaded.save(force_insert=True)
        with self.assertRaisesRegex(ImmutableLogError, "cannot be updated"):
            AuditLog(**audit_fields()).save(force_update=True)
        self.assertEqual(AuditLog.objects.count(), 1)
        self.assert_record_unchanged()

    def test_primary_key_collision_is_a_failed_insert_without_an_overwrite(self):
        same_id = AuditLog(id=self.record.pk, **audit_fields())
        with self.assertRaises(IntegrityError) as rejected, transaction.atomic():
            same_id.save()
        self.assertEqual(rejected.exception.__cause__.sqlstate, "23505")
        self.assertEqual(
            rejected.exception.__cause__.diag.constraint_name,
            "moderation_auditlog_pkey",
        )
        self.assert_record_unchanged()

    def test_queries_and_base_manager_reject_mutations(self):
        for manager in (AuditLog.objects, AuditLog._base_manager):
            query = manager.filter(pk=self.record.pk)
            with self.assertRaisesRegex(ImmutableLogError, "cannot be updated"):
                query.update(justification="Attempted change")
            with self.assertRaisesRegex(ImmutableLogError, "cannot be deleted"):
                query.delete()
            with self.assertRaisesRegex(ImmutableLogError, "cannot be updated"):
                manager.bulk_update([self.record], ["justification"])
        self.assert_record_unchanged()

    def test_bulk_conflict_options_are_rejected(self):
        collision = AuditLog(id=self.record.pk, **audit_fields())
        for kwargs in (
            {"ignore_conflicts": True},
            {
                "update_conflicts": True,
                "unique_fields": ["id"],
                "update_fields": ["justification"],
            },
        ):
            with (
                self.subTest(kwargs=kwargs),
                self.assertRaisesRegex(
                    ImmutableLogError, "do not accept conflict options"
                ),
            ):
                AuditLog.objects.bulk_create([collision], **kwargs)
        self.assert_record_unchanged()

    def test_valid_bulk_insert_is_append_only_and_other_inserts_still_work(self):
        first, second = AuditLog.objects.bulk_create(
            [AuditLog(**audit_fields()) for _ in range(2)]
        )
        self.assertNotEqual(first.pk, second.pk)
        self.assertTrue(timezone.is_aware(first.created_at))
        first.pk = uuid.uuid4()
        first._state.adding = True
        with self.assertRaisesRegex(ImmutableLogError, "only be inserted once"):
            AuditLog.objects.bulk_create([first])
        AuditLog.objects.create(**audit_fields())
        self.assertEqual(AuditLog.objects.count(), 4)
        self.assert_record_unchanged()
