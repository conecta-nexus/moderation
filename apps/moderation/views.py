import ipaddress
from datetime import UTC, datetime, time, timedelta
from functools import cached_property

from django.db import transaction
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.authentication import AuthJWTAuthentication
from apps.core.permissions import (
    CanModerateChallenge,
    CanReadAuditLog,
    CanWriteUserStatus,
    IsPlatformAdmin,
)

from .clients import (
    AuthModerationClient,
    ChallengeModerationClient,
    ModerationTargetConflictError,
    ModerationTargetNotFoundError,
    ModerationUpstreamUnavailableError,
)
from .models import ActionType, ActorRole, AuditLog, TargetType
from .pagination import AuditLogPagination
from .serializers import (
    AuditLogQuerySerializer,
    AuditLogSerializer,
    SuspensionRequestSerializer,
)


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


def _extract_client_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    candidate = forwarded.split(",")[0].strip() if forwarded else ""
    if not candidate:
        candidate = (request.META.get("REMOTE_ADDR") or "").strip()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return "127.0.0.1"


class ChallengeSuspendView(APIView):
    """Suspend a challenge upstream and record an immutable AuditLog entry."""

    authentication_classes = (AuthJWTAuthentication,)
    permission_classes = (IsAuthenticated, IsPlatformAdmin, CanModerateChallenge)
    renderer_classes = (JSONRenderer,)

    def get_challenge_client(self) -> ChallengeModerationClient:
        return ChallengeModerationClient()

    def post(self, request, challenge_id, *args, **kwargs):
        serializer = SuspensionRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        justification = serializer.validated_data["justification"]
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")

        try:
            downstream = self.get_challenge_client().suspend_challenge(
                challenge_id, justification, auth_header=auth_header
            )
        except ModerationTargetNotFoundError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_404_NOT_FOUND)
        except ModerationTargetConflictError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
        except ModerationUpstreamUnavailableError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_502_BAD_GATEWAY)

        with transaction.atomic():
            audit_entry = AuditLog.objects.create(
                actor_id=request.user.id,
                actor_email=request.user.email,
                actor_role=ActorRole.ADMIN,
                action_type=ActionType.CHALLENGE_SUSPEND,
                target_id=challenge_id,
                target_type=TargetType.CHALLENGE,
                justification=justification,
                ip_address=_extract_client_ip(request),
            )

        return Response(
            {
                "audit_log": AuditLogSerializer(audit_entry).data,
                "target": downstream,
            },
            status=status.HTTP_200_OK,
        )


class UserSuspendView(APIView):
    """Deactivate a user account upstream and record an immutable AuditLog entry."""

    authentication_classes = (AuthJWTAuthentication,)
    permission_classes = (IsAuthenticated, IsPlatformAdmin, CanWriteUserStatus)
    renderer_classes = (JSONRenderer,)

    def get_auth_client(self) -> AuthModerationClient:
        return AuthModerationClient()

    def post(self, request, user_id, *args, **kwargs):
        serializer = SuspensionRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        justification = serializer.validated_data["justification"]
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")

        try:
            downstream = self.get_auth_client().suspend_user(
                user_id, auth_header=auth_header
            )
        except ModerationTargetNotFoundError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_404_NOT_FOUND)
        except ModerationUpstreamUnavailableError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_502_BAD_GATEWAY)

        with transaction.atomic():
            audit_entry = AuditLog.objects.create(
                actor_id=request.user.id,
                actor_email=request.user.email,
                actor_role=ActorRole.ADMIN,
                action_type=ActionType.USER_SUSPEND,
                target_id=user_id,
                target_type=TargetType.USER,
                justification=justification,
                ip_address=_extract_client_ip(request),
            )

        return Response(
            {
                "audit_log": AuditLogSerializer(audit_entry).data,
                "target": downstream,
            },
            status=status.HTTP_200_OK,
        )
