from django.urls import path

from .views import AuditLogListView, ChallengeSuspendView, UserSuspendView

urlpatterns = [
    path("audit-logs/", AuditLogListView.as_view(), name="audit-log-list"),
    path(
        "challenges/<uuid:challenge_id>/suspend/",
        ChallengeSuspendView.as_view(),
        name="challenge-suspend",
    ),
    path(
        "users/<uuid:user_id>/suspend/",
        UserSuspendView.as_view(),
        name="user-suspend",
    ),
]
