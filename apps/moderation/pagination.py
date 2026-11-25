from rest_framework.pagination import PageNumberPagination


class AuditLogPagination(PageNumberPagination):
    def paginate_queryset(self, queryset, request, view=None):
        self.query = view.audit_query
        return super().paginate_queryset(queryset, request, view)

    def get_page_number(self, request, paginator):
        return self.query["page"]

    def get_page_size(self, request):
        return self.query["page_size"]

    def _page_link(self, page_number):
        params = self.request.query_params.copy()
        params["page"] = page_number
        # The Admin deployment mount is part of request.path but not this REST route.
        return f"{self.request.path_info}?{params.urlencode()}"

    def get_next_link(self):
        if self.page.has_next():
            return self._page_link(self.page.next_page_number())
        return None

    def get_previous_link(self):
        if self.page.has_previous():
            return self._page_link(self.page.previous_page_number())
        return None
