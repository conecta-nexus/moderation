import uuid
from typing import ClassVar

from django.core.exceptions import PermissionDenied
from django.core.validators import RegexValidator
from django.db import models
from django.db.models.functions import Now


class ActorRole(models.TextChoices):
    ADMIN = "ADMIN", "Administrator"


class ActionType(models.TextChoices):
    CHALLENGE_SUSPEND = "CHALLENGE_SUSPEND", "Suspend challenge"
    USER_SUSPEND = "USER_SUSPEND", "Suspend user"
    CONTENT_FLAG = "CONTENT_FLAG", "Flag content"


class TargetType(models.TextChoices):
    CHALLENGE = "CHALLENGE", "Challenge"
    USER = "USER", "User"


# Explicit characters give Django and PostgreSQL the same whitespace rules,
# independent of the PostgreSQL locale.
NON_WHITESPACE = (
    "[^\t\n\v\f\r\x1c\x1d\x1e\x1f \x85\xa0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000]"
)


class ImmutableLogError(PermissionDenied):
    """An operation attempted to change audit history."""


class AuditLogQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ImmutableLogError("Audit log records cannot be updated.")

    def delete(self):
        raise ImmutableLogError("Audit log records cannot be deleted.")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ImmutableLogError("Audit log records cannot be updated.")

    def bulk_create(
        self,
        objs,
        batch_size=None,
        ignore_conflicts=False,
        update_conflicts=False,
        update_fields=None,
        unique_fields=None,
    ):
        if ignore_conflicts or update_conflicts or update_fields or unique_fields:
            raise ImmutableLogError(
                "Audit log bulk inserts do not accept conflict options."
            )
        records = list(objs)
        for record in records:
            record._validate_insert()
        inserted = super().bulk_create(records, batch_size=batch_size)
        for record in inserted:
            record._inserted = True
        return inserted


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor_id = models.UUIDField()
    actor_email = models.EmailField()
    actor_role = models.CharField(max_length=5, choices=ActorRole)
    action_type = models.CharField(max_length=17, choices=ActionType)
    target_id = models.UUIDField()
    target_type = models.CharField(max_length=9, choices=TargetType)
    justification = models.TextField(
        validators=[
            RegexValidator(
                NON_WHITESPACE,
                "Enter a justification containing a non-whitespace character.",
                code="blank",
            ),
        ],
    )
    ip_address = models.GenericIPAddressField()
    created_at = models.DateTimeField(auto_now_add=True, db_default=Now())

    objects = AuditLogQuerySet.as_manager()
    _inserted = False

    class Meta:
        db_table = "moderation_auditlog"
        base_manager_name = "objects"
        ordering: ClassVar[list[str]] = ["-created_at", "-id"]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=models.Q(actor_role=ActorRole.ADMIN), name="audit_actor_admin"
            ),
            models.CheckConstraint(
                condition=models.Q(action_type__in=ActionType.values),
                name="audit_action_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(target_type__in=TargetType.values),
                name="audit_target_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(justification__regex=NON_WHITESPACE),
                name="audit_justification_nonblank",
            ),
            models.CheckConstraint(
                condition=models.Q(actor_email__regex=NON_WHITESPACE),
                name="audit_actor_email_nonblank",
            ),
        ]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["-created_at", "-id"], name="audit_recent_idx"),
            models.Index(
                fields=["actor_id", "-created_at"], name="audit_actor_recent_idx"
            ),
            models.Index(
                fields=["action_type", "-created_at"], name="audit_action_recent_idx"
            ),
            models.Index(
                fields=["target_type", "-created_at"], name="audit_type_recent_idx"
            ),
            models.Index(fields=["target_id"], name="audit_target_idx"),
        ]

    @classmethod
    def from_db(cls, db, field_names, values):
        record = super().from_db(db, field_names, values)
        record._inserted = True
        return record

    def _validate_insert(self):
        if self._inserted or not self._state.adding:
            raise ImmutableLogError("Audit log records can only be inserted once.")
        # The INSERT and database constraints handle uniqueness without a race-prone read.
        self.full_clean(validate_unique=False, validate_constraints=False)

    def save(
        self, *, force_insert=False, force_update=False, using=None, update_fields=None
    ):
        if force_update or update_fields is not None:
            raise ImmutableLogError("Audit log records cannot be updated.")
        self._validate_insert()
        super().save(force_insert=True, using=using)
        self._inserted = True

    def delete(self, using=None, keep_parents=False):
        raise ImmutableLogError("Audit log records cannot be deleted.")
