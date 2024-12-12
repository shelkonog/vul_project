from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('', views.CVEListView.as_view(), name='home'),
    path('<int:pk>/', views.CVEDetailView.as_view(), name='cve_detail'),
    path('search/', views.CVESearchView.as_view(), name='cve_search'),
    path('search/<int:pk>/', views.CVEDetailView.as_view(), name='cve_detail'),
    path('ajax', views.get_ajax_query, name='ajax'),
    path('ajax_ver', views.get_ajax_ver_query, name='ajax_ver'),
    path('soft/', views.SoftListView.as_view(), name='cve_soft'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
