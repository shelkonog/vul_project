from django.urls import path
from . import views
# from django.conf import settings
# from django.conf.urls.static import static


urlpatterns = [
    path('', views.CVEListView.as_view(), name='home'),
    path('<int:pk>/', views.CVEDetailView.as_view(), name='cve_detail'),
    path('search/', views.CVESearchView.as_view(), name='cve_search'),
    path('search/<int:pk>/', views.CVEDetailView.as_view(), name='cve_detail'),
    path('ajax', views.get_ajax_query, name='ajax'),
    path('ajax_ver', views.get_ajax_ver_query, name='ajax_ver'),
    path('soft/', views.SoftListView.as_view(), name='cve_soft'),
    path('vul/', views.SearchBullitenView.as_view(), name='vul_list'),
    path('vul/<str:hit_id>/', views.DetailBulView.as_view(), name='audit_detail'),
    path('audit/', views.AuditLinuxView.as_view(), name='audit_bul'),
    path('audit/<str:hit_id>/', views.DetailBulView.as_view(), name='audit_detail'),
    path('pdf/<str:os_pack>/', views.PdfView.as_view(), name='pdf_view'),
]
