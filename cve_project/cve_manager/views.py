from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, DetailView
from django.http import JsonResponse, HttpResponse
from cve_manager.templatetags import query_transform
from django.shortcuts import render
from datetime import datetime
from . models import Vul_tbl, Soft_tbl, Soft_type_tbl, Soft_name_tbl
from . search_query import connect_to_OS, get_search_query
from django.core.paginator import Paginator
from pathlib import Path
import environ

register = query_transform
list_responce = []



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
        year = datetime.today().year
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


def search_bulliten(request):
    format_data = "%Y-%m-%dT%H:%M:%S"
    context = {}
    vul_lst = None
    env = environ.Env()
    environ.Env.read_env(env_file=Path('./cve_docker/.env'))
    global list_responce
    num_pag = 4

    adress = eval(env('ES_ADDRESS'))
    auth = tuple((env('ES_AUTH')).split())

    index_name = 'os_bulletins'
    query_dict = request.GET.get('q1')
    if query_dict:
        search_word = query_dict
    else:
        search_word = ''

    client = connect_to_OS(auth, adress)
    response = get_search_query(search_word, index_name, client)

    # преобразование метки времени из строки формата ISO в дату
    for hit in response:
        hit.published = datetime.strptime(hit.published, format_data)

    list_responce = list(response)
    paginator = Paginator(list_responce, num_pag)

    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    if page_obj:
        if not page_number:
            vul_range = range(1, num_pag+1)
        else:
            vul_range = range(paginator.page(page_number).start_index(), paginator.page(page_number).end_index()+1)
        vul_lst = list(vul_range)
    else:
        vul_lst = None

    if (page_obj or vul_lst) is not None:
        page_obj_all = zip(page_obj, vul_lst)
    else:
        page_obj_all = None
    context['page_obj'] = page_obj
    context['page_obj_all'] = page_obj_all

    context['vul'] = len(list_responce)
    context['vul_total'] = response.hits.total.value

    return render(request, 'bulletin.html', context)


def detail_bulliten(request, hit_id):
    global list_responce
    context = {}
    if list_responce and hit_id > 0:
        context['vul_hit_id'] = list_responce[hit_id - 1].to_dict()

    return render(request, 'bulletin_detail.html', context)
