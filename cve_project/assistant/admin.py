from django.contrib import admin
from .models import help_tbl
from django.utils.html import linebreaks


@admin.register(help_tbl)
class VulTblAdmin(admin.ModelAdmin):
    list_display = ('tag', 'topic', 'topic_number', 'content')
    # list_filter = ('identifier', 'identify_date', 'severity', 'solution')
    # search_fields = ('identifier', 'identify_date')
    # #date_hierarchy = 'identify_date'
    # ordering = ('-id', 'identifier')

    def content(self, instance):
        return linebreaks(instance.content)
    content.short_description = 'Описание'
    content.allow_tags = True
