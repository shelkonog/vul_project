from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render
from django.views.generic import ListView, DetailView
from django.db.models import F
from django.http import JsonResponse, HttpResponse
from . models import Vul_tbl, Soft_tbl, Soft_type_tbl, Soft_name_tbl


class SoftListView(LoginRequiredMixin, ListView):
    model = Soft_tbl
    template_name = 'bdu_soft.html'
    paginate_by = 6
    login_url = 'login'


class CVEListView(LoginRequiredMixin, ListView):
    model = Vul_tbl
    template_name = 'bdu.html'
    paginate_by = 4
    login_url = 'login'

    def get_context_data(self, **kwargs):
        context = super(CVEListView, self).get_context_data(**kwargs)
        context['soft_type'] = Soft_type_tbl.objects.all()
        return context


def get_ajax_query(request):
    context = []
    search = request.GET.get('q')
    resp = Soft_name_tbl.objects.all()
    resp = resp.filter(soft_name__icontains=search)
    resp2 = resp.order_by().values_list('soft_name', flat=True).distinct()
    for i in resp2:
        context.append({'id': i, 'text': i})
    return JsonResponse({'results': context}, safe=False)


def get_ajax_ver_query(request):
    context = []
    search = request.GET.get('q')
    if search:
        resp = Soft_name_tbl.objects.all()
        resp = resp.filter(soft_name__icontains=search)
        resp2 = resp.values_list('soft_version', flat=True)
        for i in resp2:
            context.append({'id': i, 'text': i})
    return JsonResponse({'results': context}, safe=False)


class CVEDetailView(LoginRequiredMixin, DetailView):
    model = Vul_tbl
    template_name = 'cve_detail.html'
    login_url = 'login'

    def get_context_data(self, **kwargs):
        context = super(CVEDetailView, self).get_context_data(**kwargs)
        cve_id = context['object']
        context['soft_tbl'] = Soft_tbl.objects.filter(identifier__exact=cve_id)
        context['soft_vendor_dist'] = context['soft_tbl'].order_by().values_list('soft_vendor', flat=True).distinct()
        context['soft_name_dist'] = context['soft_tbl'].order_by().values_list('soft_name', flat=True).distinct()
        context['soft_type_dist'] = context['soft_tbl'].order_by().values_list('soft_type', flat=True).distinct()
        return context


class CVESearchView(LoginRequiredMixin, ListView):
    model = Vul_tbl
    template_name = 'cve_search.html'
    paginate_by = 4
    login_url = 'login'

    def get_queryset(self, ):
        queryset = super().get_queryset()
        search1 = self.request.GET.get('q1')
        search2 = self.request.GET.get('q2')
        search3 = self.request.GET.get('q3')
        search4 = self.request.GET.get('q4')
        if search1:
            queryset = queryset.filter(identifier__icontains=search1)
        if search2:
            queryset = queryset.filter(softs__soft_type=search2)
        if search3:
            queryset = queryset.filter(softs__soft_name=search3)
            if search4:
                queryset = queryset.filter(softs__soft_version=search4)
        return queryset
