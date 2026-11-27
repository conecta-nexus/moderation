import re
from datetime import UTC, date

from rest_framework import serializers

from .models import ActionType, AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default_timezone=UTC, read_only=True)

    class Meta:
        model = AuditLog
        fields = (
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
        read_only_fields = fields


class QueryIntegerField(serializers.IntegerField):
    def to_internal_value(self, data):
        if not re.fullmatch(r"[0-9]+", str(data)):
            self.fail("invalid")
        return super().to_internal_value(data)


class QueryDateField(serializers.DateField):
    def to_internal_value(self, data):
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", str(data)):
            raise serializers.ValidationError(
                "Use a calendar date in YYYY-MM-DD format."
            )
        return super().to_internal_value(data)


class AuditLogQuerySerializer(serializers.Serializer):
    page = QueryIntegerField(required=False, min_value=1, default=1)
    page_size = QueryIntegerField(
        required=False, min_value=1, max_value=100, default=20
    )
    action_type = serializers.ChoiceField(choices=ActionType.choices, required=False)
    actor_id = serializers.UUIDField(required=False)
    start_date = QueryDateField(required=False)
    end_date = QueryDateField(required=False)

    def validate_end_date(self, value):
        if value == date.max:
            raise serializers.ValidationError("Use an end date before 9999-12-31.")
        return value

    def validate(self, attrs):
        start, end = attrs.get("start_date"), attrs.get("end_date")
        if start and end and start > end:
            raise serializers.ValidationError(
                {"end_date": "End date must be on or after start date."}
            )
        return attrs
