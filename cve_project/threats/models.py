from django.db import models


class Measure(models.Model):
    id_sec_measure = models.CharField(unique=True)
    sec_measure = models.CharField()
    sub_gr_measure = models.CharField()
    gr_measure = models.CharField()

    class Meta:
        db_table = "sec_measure_tbl"
        ordering = ('-id',)
        managed = True

    def __str__(self):
        return self.id_sec_measure
