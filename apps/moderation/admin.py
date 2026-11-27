from datetime import date, datetime, time, timedelta
from uuid import UUID

from django import forms
from django.contrib import admin
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Q
from django.utils import timezone
from django.utils.html import format_html

from .models import AuditLog


class AuditDateRangeForm(forms.Form):
    start_date = forms.DateField(
        label="Desde",
        required=False,
        input_formats=["%Y-%m-%d"],
        widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        error_messages={"invalid": "Ingresa una fecha válida."},
    )
    end_date = forms.DateField(
        label="Hasta",
        required=False,
        input_formats=["%Y-%m-%d"],
        widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        error_messages={"invalid": "Ingresa una fecha válida."},
    )

    def clean(self):
        values = super().clean()
        start, end = values.get("start_date"), values.get("end_date")
        if start and end and start > end:
            raise ValidationError(
                "La fecha de inicio debe ser anterior o igual a la fecha final."
            )
        if end == date.max:
            self.add_error(
                "end_date", "Selecciona una fecha anterior al 31 de diciembre de 9999."
            )
        return values


class AuditDateRangeFilter(admin.SimpleListFilter):
    title = "Fecha de creación"
    parameter_name = "start_date"
    template = "admin/moderation/auditlog/date_filter.html"

    def __init__(self, request, params, model, model_admin):
        super().__init__(request, params, model, model_admin)
        end = params.pop("end_date", None)
        if end:
            self.used_parameters["end_date"] = end[-1]
        self.form = AuditDateRangeForm(self.used_parameters or None)
        excluded = {"start_date", "end_date", "p", "all"}
        self.preserved_params = [
            (key, value)
            for key, values in request.GET.lists()
            if key not in excluded
            for value in values
        ]

    def lookups(self, request, model_admin):
        return ()

    def has_output(self):
        return True

    def expected_parameters(self):
        return ["start_date", "end_date"]

    def choices(self, changelist):
        yield {
            "clear_url": changelist.get_query_string(remove=self.expected_parameters())
        }

    def queryset(self, request, queryset):
        if not self.form.is_bound:
            return queryset
        if not self.form.is_valid():
            return queryset.none()

        start = self.form.cleaned_data["start_date"]
        end = self.form.cleaned_data["end_date"]
        zone = timezone.get_default_timezone()
        if start:
            queryset = queryset.filter(
                created_at__gte=datetime.combine(start, time.min, zone)
            )
        if end:
            next_day = datetime.combine(end + timedelta(days=1), time.min, zone)
            queryset = queryset.filter(created_at__lt=next_day)
        return queryset


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "actor_email",
        "action_label",
        "target_label",
        "target_id",
    )
    list_filter = ("action_type", "target_type", AuditDateRangeFilter)
    ordering = ("-created_at", "-id")
    sortable_by = ()
    list_per_page = 20
    list_max_show_all = 0
    show_full_result_count = False
    show_facets = admin.ShowFacets.NEVER
    search_fields = ("actor_email", "target_id", "justification")
    search_help_text = (
        "Busca por correo del actor, UUID completo del objetivo o justificación."
    )
    actions = None

    readonly_fields = (
        "id",
        "created_at",
        "actor_id",
        "actor_email",
        "actor_role_value",
        "action_value",
        "target_id",
        "target_value",
        "justification",
        "ip_address",
    )
    fieldsets = (
        ("Registro", {"fields": ("id", "created_at", "action_value")}),
        (
            "Actor",
            {"fields": ("actor_id", "actor_email", "actor_role_value", "ip_address")},
        ),
        ("Objetivo", {"fields": ("target_id", "target_value")}),
        ("Justificación", {"fields": ("justification",)}),
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_view_permission(self, request, obj=None):
        return self.admin_site.has_permission(request) and request.user.has_perm(
            "moderation.view_auditlog"
        )

    def changelist_view(self, request, extra_context=None):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            raise PermissionDenied
        return super().changelist_view(request, extra_context)

    def get_search_results(self, request, queryset, search_term):
        term = search_term.strip()
        if not term:
            return queryset, False
        matches = Q(actor_email__icontains=term) | Q(justification__icontains=term)
        try:
            target_id = UUID(term)
        except ValueError:
            pass
        else:
            matches |= Q(target_id=target_id)
        return queryset.filter(matches), False

    @admin.display(description="Acción")
    def action_label(self, record):
        return record.get_action_type_display()

    @admin.display(description="Tipo de objetivo")
    def target_label(self, record):
        return record.get_target_type_display()

    @admin.display(description="Acción")
    def action_value(self, record):
        return format_html(
            "{} <code>{}</code>", self.action_label(record), record.action_type
        )

    @admin.display(description="Tipo de objetivo")
    def target_value(self, record):
        return format_html(
            "{} <code>{}</code>", self.target_label(record), record.target_type
        )

    @admin.display(description="Rol del actor")
    def actor_role_value(self, record):
        return record.actor_role
