from django.views.generic import ListView
from django.contrib.auth.mixins import LoginRequiredMixin
from . models import Measure


class MeasureListView(LoginRequiredMixin, ListView):
    model = Measure
    template_name = 'threate.html'
    login_url = 'login'

    def get_context_data(self, **kwargs):
        context = super(MeasureListView, self).get_context_data(**kwargs)
        last_gr, last_sub = None, None
        measure = {}
        for i in Measure.objects.all():
            if last_gr != i.gr_measure:
                last_gr = i.gr_measure
                measure[last_gr] = {i.sub_gr_measure: {i.id_sec_measure: i.sec_measure}}
            elif last_sub != i.sub_gr_measure:
                last_sub = i.sub_gr_measure
                measure[last_gr][last_sub] = {i.id_sec_measure: i.sec_measure}
            else:
                measure[last_gr][last_sub][i.id_sec_measure] = i.sec_measure

            measure_sort = sorted(measure.items())
            measure = dict(measure_sort)

            for key, value in measure.items():
                measure_sort = sorted(value.items())
                measure[key] = dict(measure_sort)
                for key2, value2 in value.items():
                    measure_sort = sorted(value2.items())
                    measure[key][key2] = dict(measure_sort)

        context['measure'] = measure

        return context
