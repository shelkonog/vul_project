from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, DetailView, TemplateView
from django.http import JsonResponse
from cve_manager.templatetags import query_transform
from datetime import datetime
from . models import Vul_tbl, Soft_tbl, Soft_type_tbl, Soft_name_tbl
from . search_query import get_search_query, get_pack_query, get_detail_query, get_bdu_detail_query, get_bdu_linux_query
from django.core.paginator import Paginator
import rpm_vercmp
from pydpkg import Dpkg
from django_weasyprint import WeasyTemplateResponseMixin

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


class SearchBullitenView(LoginRequiredMixin, TemplateView):
    template_name = 'bulletin.html'
    login_url = 'login'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        list_response = []
        format_data = "%Y-%m-%dT%H:%M:%S"
        format_data_timestamp = "%Y-%m-%d"
        stat_db = {}
        vul_lst = None
        num_pag = 4

        query_word = self.request.GET.get('q1')
        query_date = self.request.GET.get('date')
        query_count = self.request.GET.get('count')

        if not query_word:
            query_word = ""
        if not query_date:
            query_date = 12
        if not query_count:
            query_count = 20

        try:
            response = get_search_query(query_word, query_date, query_count)
        except Exception as exc:
            print('Ошибка при работе с СУБД OpenSearche', exc.args)
            response = "Error"

        # преобразование метки времени из строки формата ISO в дату
        if response and response != 'Error':
            for hit in response:
                hit.published = datetime.strptime(hit.published, format_data)
            list_response = list(response)
            context['vul_total'] = response.hits.total.value
            context['error'] = None
        elif response == 'Error':
            list_response = []
            context['vul_total'] = 0
            context['error'] = "Ошибка при обработке данных!!!"
        else:
            list_response = []
            context['vul_total'] = 0
            context['error'] = None

        paginator = Paginator(list_response, num_pag)

        page_number = self.request.GET.get("page")
        page_obj = paginator.get_page(page_number)

        if page_obj:
            if not page_number:
                vul_range = range(1, num_pag+1)
            else:
                vul_range = range(paginator.page(page_number).start_index(), paginator.page(page_number).end_index()+1)
            vul_lst = list(vul_range)
        else:
            vul_lst = None

        # Создание списка страниц и сквозной нумерации бюлетеней
        if (page_obj or vul_lst) is not None:
            page_obj_all = zip(page_obj, vul_lst)
        else:
            page_obj_all = None

        try:
            resp_stat_db = get_bdu_detail_query()
        except Exception as exc:
            print('Ошибка при работе с СУБД OpenSearche', exc.args)
            resp_stat_db = "Error"

        if resp_stat_db != "Error":
        # формирование информации о базах бюлетеней
            for hit in resp_stat_db.aggregations.by_type.buckets:
                temp_date = hit.group_docs.hits.hits[0]._source['@timestamp'].split('T')
                date_format = datetime.strptime(temp_date[0], format_data_timestamp)
                stat_db.update({hit.key: [hit.doc_count, date_format]})
        else:
            context['error'] = "Ошибка при обработке данных!!!"
            stat_db = None

        # перечень баз бюлетеней с кол-вом и меткой времени
        context['stat_db'] = stat_db
        # Список объектов для пагинации
        context['page_obj'] = page_obj
        # Список объектов для вывода и нумерации
        context['page_obj_all'] = page_obj_all

        # Кол-во загруженных для отображения бюлетеней
        context['vul'] = len(list_response)

        # Сохранить на странице параметры запроса
        context['word'] = query_word    # Поисковый запрос
        context['date'] = query_date    # Параметры времени
        context['count'] = query_count  # Мак кол-во бюлетеней в результате поиска

        return context


class AuditLinuxView(LoginRequiredMixin, TemplateView):
    template_name = 'bulletin_pack.html'
    login_url = 'login'

    def get_lst_OS(self):
        lst_os_name = [["debian", "deb"],
                       ["ubuntu", "deb"],
                       ["redos", "rpm"],
                       ["RedHat", "rpm"]]

        return lst_os_name

    def get_lst_pack(self, query_pack):
        if query_pack:
            lst_words = query_pack.splitlines()
            lst_pack = [word.split() for word in lst_words]
        else:
            lst_pack = None
        return lst_pack

    def get_name_ver_pack(self, pack):
        if len(pack) in (2, 3):
            packageName = pack[0]
            v_real = pack[1]
        elif len(pack) == 1:
            packageName = pack[0]
            v_real = None
        else:
            packageName, v_real = None, None
        return packageName, v_real

    def get_actual_cve(self, response, packageName, v_real, query_OS):
        rez_pack_cve = {}
        if response:
            for hit in response:
                for key in hit.affectedPackage:
                    if key.packageName == packageName:
                        v_db = key.packageVersion
                        if query_OS[1] == "deb":
                            comp_rez = Dpkg.compare_versions(v_db, v_real)
                        else:
                            comp_rez = rpm_vercmp.vercmp(v_db, v_real)
                        if comp_rez >= 0:
                            if packageName + " " + v_real in rez_pack_cve:
                                rez_pack_cve[packageName + " " + v_real].append(hit)
                            else:
                                rez_pack_cve[packageName + " " + v_real] = []
                                rez_pack_cve[packageName + " " + v_real].append(hit)

                            break
        else:
            rez_pack_cve = {}
        return rez_pack_cve

    def get_dbu_info(self, ):
        format_data_timestamp = "%Y-%m-%d"
        stat_db = {}
        try:
            resp_stat_db = get_bdu_linux_query()
        except Exception as exc:
            print('Ошибка при работе с СУБД OpenSearche', exc.args)
            resp_stat_db = "Error"

        if resp_stat_db != "Error":
        # формирование информации о базах бюлетеней
            for hit in resp_stat_db.aggregations.by_type.buckets:
                temp_date = hit.group_docs.hits.hits[0]._source['@timestamp'].split('T')
                date_format = datetime.strptime(temp_date[0], format_data_timestamp)
                stat_db.update({hit.key: [hit.doc_count, date_format]})
        else:
            # context['error'] = "Ошибка при обработке данных!!!"
            stat_db = None
        return stat_db

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        rez_pack_cve, pack_cve = {}, {}
        count_cve, count_cve_act = 0, 0
        stat_db = {}
        response = None

        index_OS = self.request.GET.get("OS")
        query_pack = self.request.GET.get("pack")

        if index_OS:
            query_OS = self.get_lst_OS()[int(index_OS)]
        else:
            query_OS = ""

        lst_pack = self.get_lst_pack(query_pack)

        if lst_pack:
            for pack in lst_pack:
                packageName, v_real = self.get_name_ver_pack(pack)
                if packageName and v_real:
                    try:
                        response = get_pack_query(packageName, query_OS[0])
                    except Exception as exc:
                        print('Ошибка при работе с СУБД OpenSearche', exc.args)
                        response = "Error"
                        break
                    if response:
                        count_cve = count_cve + response.hits.total.value
                        pack_cve = self.get_actual_cve(response, packageName, v_real, query_OS)
                        rez_pack_cve.update(pack_cve)
            context["query_OS_pdf"] = index_OS + "\r\n" + str(query_pack) + "\r\n"
        else:
            context["query_OS_pdf"] = None

        if rez_pack_cve and response != 'Error':
            for pack_cve in rez_pack_cve.values():
                count_cve_act = count_cve_act + len(pack_cve)

        stat_db = self.get_dbu_info()

        if stat_db:
            # перечень баз бюлетеней с кол-вом и меткой времени
            context['stat_db'] = stat_db
        else:
            context['error'] = "Ошибка при обработке данных!!!"

        if response != 'Error':
            context["dict_hit"] = rez_pack_cve  # Словарь с актуальными бюлетенями для пакета
            context['vul_total'] = count_cve    # Перечень всего найденных бюлетеней
            context['vul_act'] = count_cve_act  # Перечень актуальных бюлетеней
            context["lst_OS"] = self.get_lst_OS()   # Выбраный тип ОС для поиска бюлетеней
            context["lst_pack"] = lst_pack  # Перечень пакетов из поискового запроса
            context['error'] = None
        else:
            context["dict_hit"] = {}
            context['vul_total'] = 0
            context['vul_act'] = 0
            context["lst_OS"] = []
            context["lst_pack"] = []
            context['error'] = "Ошибка при обработке данных!!!"

        return context


class DetailBulView(LoginRequiredMixin, TemplateView):
    template_name = 'bulletin_detail.html'
    login_url = 'login'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        hit_id = self.kwargs['hit_id']
        context['error'] = None
        response = ""

        try:
            response = get_detail_query(hit_id)
        except Exception as exc:
            print('Ошибка при работе с СУБД OpenSearche', exc.args)
            response = "Error"

        if response and response != 'Error':
            context['vul_hit_id'] = response.to_dict()['hits']['hits'][0]['_source']
        elif response != 'Error':
            context['vul_hit_id'] = None
        else:
            context['vul_hit_id'] = None
            context['error'] = "Ошибка при обработке данных!!!"

        return context


class PdfView(LoginRequiredMixin, WeasyTemplateResponseMixin, TemplateView):
    template_name = "pdfview.html"
    login_url = 'login'

    def get_lst_OS(self):
        lst_os_name = [["debian", "deb"],
                       ["ubuntu", "deb"],
                       ["redos", "rpm"],
                       ["RedHat", "rpm"]]

        return lst_os_name

    def get_name_ver_pack(self, pack):
        if len(pack) == 3:
            packageName = pack[0]
            v_real = pack[1]
        else:
            packageName, v_real = None, None
        return packageName, v_real

    def get_actual_cve(self, response, packageName, v_real, query_OS):
        rez_pack_cve = {}
        if response:
            for hit in response:
                for key in hit.affectedPackage:
                    if key.packageName == packageName:
                        v_db = key.packageVersion
                        if query_OS[1] == "deb":
                            comp_rez = Dpkg.compare_versions(v_db, v_real)
                        else:
                            comp_rez = rpm_vercmp.vercmp(v_db, v_real)
                        if comp_rez >= 0:
                            if packageName + " " + v_real in rez_pack_cve:
                                rez_pack_cve[packageName + " " + v_real].append(hit)
                            else:
                                rez_pack_cve[packageName + " " + v_real] = []
                                rez_pack_cve[packageName + " " + v_real].append(hit)

                            break
        else:
            rez_pack_cve = {}
        return rez_pack_cve

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        rez_pack_cve, pack_cve = {}, {}
        count_cve = 0

        query_os_pack = self.kwargs['os_pack']

        lst_words = query_os_pack.splitlines()

        index_OS = lst_words[0]
        lst_words = lst_words[1:]
        lst_pack = [word.split() for word in lst_words]
        query_OS = self.get_lst_OS()[int(index_OS)]

        if lst_pack:
            for pack in lst_pack:
                packageName, v_real = self.get_name_ver_pack(pack)
                if packageName and v_real:
                    response = get_pack_query(packageName, query_OS[0])
                    if response:
                        count_cve = count_cve + response.hits.total.value
                        pack_cve = self.get_actual_cve(response, packageName, v_real, query_OS)
                        rez_pack_cve.update(pack_cve)

        context["dict_hit"] = rez_pack_cve
        return context
