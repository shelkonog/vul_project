from django.db import models


# Create your models here.
class Vul_tbl(models.Model):
    identifier = models.CharField(max_length=20)
    name = models.CharField(max_length=200)
    description = models.CharField(max_length=200)
    cwe_identifier = models.CharField(max_length=200)
    identify_date = models.DateField()
    cvss_score = models.CharField(max_length=200)
    cvss_text = models.CharField(max_length=200)
    cvss3_score = models.CharField(max_length=200)
    cvss3_text = models.CharField(max_length=200)
    severity = models.CharField(max_length=200)
    solution = models.CharField(max_length=200)
    vul_status = models.CharField(max_length=200)
    exploit_status = models.CharField(max_length=200)
    fix_status = models.CharField(max_length=200)
    sources = models.CharField(max_length=200)
    identifiers = models.CharField(max_length=200)
    other = models.CharField(max_length=200)
    vul_incident = models.CharField(max_length=200)
    vul_class = models.CharField(max_length=200)

    class Meta:
        db_table = "cve_tbl_rez"
        ordering = ('-id',)
        managed = False

    def __str__(self):
        return self.identifier
