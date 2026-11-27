"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.conf import settings
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import include, path

admin.site.site_header = "Conecta Nexus · Administración"
admin.site.site_title = "Conecta Nexus"
admin.site.index_title = "Administración institucional"
admin.site.site_url = None

urlpatterns = [
    path("", include("apps.core.urls")),
    path("admin/", admin.site.urls),
]

# When FORCE_SCRIPT_NAME is set and a reverse proxy strips the mount prefix,
# StaticFilesHandler ignores stripped /static/ requests because its base_url
# includes the prefix. Register the stripped static route in DEBUG mode only.
if settings.DEBUG:
    urlpatterns += staticfiles_urlpatterns("/static/")
