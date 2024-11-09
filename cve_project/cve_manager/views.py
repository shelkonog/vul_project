from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render
from django.views.generic import ListView, DetailView
from . models import Vul_tbl


class CVEListView(LoginRequiredMixin, ListView):
    model = Vul_tbl
    template_name = 'bdu.html'
    paginate_by = 4
    login_url = 'login'


class CVEDetailView(LoginRequiredMixin, DetailView):
    model = Vul_tbl
    template_name = 'cve_detail.html'
    login_url = 'login'


class CVESearchView(LoginRequiredMixin, ListView):
    model = Vul_tbl
    template_name = 'cve_search.html'
    paginate_by = 4
    login_url = 'login'

    def get_queryset(self, ):
        queryset = super().get_queryset()
        search = self.request.GET.get('q')
        if search:
            return queryset.filter(identifier__icontains=search)
        else:
            return queryset.filter(identifier='no result found')
