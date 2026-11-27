from datetime import UTC, datetime, time, timedelta
from functools import cached_property

from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer

from apps.core.authentication import AuthJWTAuthentication
from apps.core.permissions import CanReadAuditLog, IsPlatformAdmin

from .models import AuditLog
from .pagination import AuditLogPagination
from .serializers import AuditLogQuerySerializer, AuditLogSerializer


class AuditLogListView(ListAPIView):
    authentication_classes = (AuthJWTAuthentication,)
    permission_classes = (IsAuthenticated, IsPlatformAdmin, CanReadAuditLog)
    serializer_class = AuditLogSerializer
    pagination_class = AuditLogPagination
    queryset = AuditLog.objects.all()
    renderer_classes = (JSONRenderer,)

    @cached_property
    def audit_query(self):
        params = self.request.query_params
        query = AuditLogQuerySerializer(data=params.dict())
        duplicates = {
            name: ["Supply this parameter only once."]
            for name in query.fields
            if len(params.getlist(name)) > 1
        }
        if duplicates:
            raise ValidationError(duplicates)
        query.is_valid(raise_exception=True)
        return query.validated_data

    def get_queryset(self):
        query = self.audit_query
        filters = {
            field: query[field]
            for field in ("actor_id", "action_type")
            if field in query
        }
        if "start_date" in query:
            filters["created_at__gte"] = datetime.combine(
                query["start_date"], time.min, UTC
            )
        if "end_date" in query:
            next_day = query["end_date"] + timedelta(days=1)
            filters["created_at__lt"] = datetime.combine(next_day, time.min, UTC)
        return super().get_queryset().filter(**filters)
