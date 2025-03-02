from django.urls import path
from . import views


urlpatterns = [
    path('', views.MeasureListView.as_view(), name='measures'),
]
