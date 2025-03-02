from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, DetailView
from . models import help_tbl

# Create your views here.
class FieldListView(LoginRequiredMixin, ListView):
    model = help_tbl
    template_name = 'help.html'
    login_url = 'login'

    def get_context_data(self, **kwargs):
        context = super(FieldListView, self).get_context_data(**kwargs)
        context["fields"] = help_tbl.objects.filter(tag__exact="fields")
        return context


class QueryListView(LoginRequiredMixin, ListView):
    model = help_tbl
    template_name = 'help.html'
    login_url = 'login'

    def get_context_data(self, **kwargs):
        context = super(QueryListView, self).get_context_data(**kwargs)
        context["fields"] = help_tbl.objects.filter(tag__exact="query")
        return context

class CVSSListView(LoginRequiredMixin, ListView):
    model = help_tbl
    template_name = 'help.html'
    login_url = 'login'

    def get_context_data(self, **kwargs):
        context = super(CVSSListView, self).get_context_data(**kwargs)
        context["fields"] = help_tbl.objects.filter(tag__exact="cvss")
        return context
