from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, DetailView
from django.http import JsonResponse
import datetime
from cve_manager.templatetags import query_transform
from . models import Vul_tbl, Soft_tbl, Soft_type_tbl, Soft_name_tbl, Bulletin

register = query_transform


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
        level = ['Критический', 'Высокий', 'Средний', 'Низкий', 'Нет опасности']
        year = datetime.datetime.today().year
        year_list = list(range(year, year-35, -1))

        context = super(CVEListView, self).get_context_data(**kwargs)

        context['soft_type'] = Soft_type_tbl.objects.all()
        context['severity'] = level
        context['year_cve'] = year_list
        return context


def get_ajax_query(request):
    #todo объединить повторяющиейся код
    context = []
    search = request.GET.get('q')
    resp = Soft_name_tbl.objects.all()
    resp = resp.filter(soft_name__icontains=search)
    resp2 = resp.order_by().values_list('soft_name', flat=True).distinct()
    for i in resp2:
        context.append({'id': i, 'text': i})
    return JsonResponse({'results': context}, safe=False)


def get_ajax_ver_query(request):
    #todo объединить повторяющиейся код
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
        qury_dict = self.request.GET

        if qury_dict['q1']:
            queryset = queryset.filter(identifier__icontains=qury_dict['q1'])
        if qury_dict['q2']:
            queryset = queryset.filter(softs__soft_type=qury_dict['q2'])
        if qury_dict['q3']:
            queryset = queryset.filter(softs__soft_name=qury_dict['q3'])
            if 'q4' in qury_dict:
                if qury_dict['q4']:
                    queryset = queryset.filter(softs__soft_version=qury_dict['q4'])
        if qury_dict['q5']:
            queryset = queryset.filter(severity__icontains=qury_dict['q5'])
        if qury_dict['q6']:
            queryset = queryset.filter(identify_date__year=qury_dict['q6'])

        return queryset


class BulletinSearchView(LoginRequiredMixin, ListView):
    model = Bulletin
    template_name = 'bulletin.html'
    paginate_by = 4
    login_url = 'login'
