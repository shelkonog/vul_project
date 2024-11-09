from django.contrib import admin
from .models import Vul_tbl


@admin.register(Vul_tbl)
class VulTblAdmin(admin.ModelAdmin):
    list_display = ('identifier', 'name', 'identify_date', 'severity', 'solution')
    list_filter = ('identifier', 'identify_date', 'severity', 'solution')
    search_fields = ('identifier', 'identify_date')
    #date_hierarchy = 'identify_date'
    ordering = ('-id', 'identifier')
