from django.contrib import admin
from django.urls import path, include


urlpatterns = [
    path('', include('cve_manager.urls')),
    path('measures/', include('threats.urls')),
    path('help/', include('assistant.urls')),
    path('admin/', admin.site.urls),
    path('users/', include('django.contrib.auth.urls')),
]

admin.site.site_header = "Панель администрирования"
admin.site.index_title = "Приложение для работы с уязвимостями"
