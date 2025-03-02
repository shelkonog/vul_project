from django.urls import path
from . import views
# from django.conf import settings
# from django.conf.urls.static import static


urlpatterns = [
    path('', views.FieldListView.as_view(), name='fields'),
    path('query', views.QueryListView.as_view(), name='query'),
    path('cvss', views.CVSSListView.as_view(), name='cvss'),
]
