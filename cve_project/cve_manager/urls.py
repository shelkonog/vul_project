from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('', views.CVEListView.as_view(), name='home'),
    path('<int:pk>/', views.CVEDetailView.as_view(), name='cve_detail'),
    path('search/', views.CVESearchView.as_view(), name='cve_search'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
