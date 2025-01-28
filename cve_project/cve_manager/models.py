from django.db import models


# Create your models here.
class Vul_tbl(models.Model):
    identifier = models.CharField(max_length=255, unique=True)
    name = models.CharField()
    description = models.CharField(null=True)
    cwe_identifier = models.CharField(null=True)
    identify_date = models.DateField(null=True)
    cvss_score = models.CharField(null=True)
    cvss_text = models.CharField(null=True)
    cvss3_score = models.CharField(null=True)
    cvss3_text = models.CharField(null=True)
    severity = models.CharField(null=True)
    solution = models.CharField(null=True)
    vul_status = models.CharField(null=True)
    exploit_status = models.CharField(null=True)
    fix_status = models.CharField(null=True)
    sources = models.CharField(null=True)
    identifiers = models.CharField(null=True)
    other = models.CharField(null=True)
    vul_incident = models.CharField(null=True)
    vul_class = models.CharField(null=True)

    class Meta:
        db_table = "cve_tbl_rez"
        ordering = ('-id',)
        managed = True

    def __str__(self):
        return self.identifier


class Soft_tbl(models.Model):
    identifier = models.ForeignKey(Vul_tbl,
                                   to_field='identifier',
                                   on_delete=models.PROTECT,
                                   related_name='softs')
    soft_vendor = models.CharField(null=True)
    soft_name = models.CharField(null=True)
    soft_version = models.CharField(null=True)
    soft_platform = models.CharField(null=True)
    soft_type = models.CharField(null=True)

    class Meta:
        db_table = "soft_tbl_rez"
        ordering = ('-id',)
        managed = True

    def __str__(self):
        return self.identifier


class Soft_type_tbl(models.Model):
    soft_type = models.CharField(null=False)

    class Meta:
        db_table = "tbl_soft_type_rez"
        ordering = ('-id',)
        managed = True

    def __str__(self):
        return self.soft_type


class Soft_name_tbl(models.Model):
    soft_name = models.CharField(null=False)
    soft_version = models.CharField(null=False)

    class Meta:
        db_table = "tbl_soft_name_rez"
        ordering = ('-id',)
        managed = True

    def __str__(self):
        return self.soft_name


class Bulletin(models.Model):
    title = models.CharField()
    description = models.CharField()
    vendorId = models.CharField()
    type = models.CharField()
    bulletinFamily = models.CharField()
    published = models.DateField()
    affectedSoftware = models.CharField()
    affectedPackage = models.CharField()
    affectedPackage = models.CharField()
    vulnStatus = models.CharField()
    cvss3 = models.CharField()
