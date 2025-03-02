from django.db import models


class help_tbl(models.Model):
    tag = models.CharField(max_length=255)
    topic = models.CharField()
    topic_number = models.SmallIntegerField()
    content = models.TextField()

    class Meta:
        verbose_name = "Справка по приложению"
        verbose_name_plural = "Справка по приложению"
        db_table = "help_tbl"
        ordering = ('-id',)
        managed = True

    def __str__(self):
        return self.topic
