# Generated by Django 5.0.7 on 2024-11-23 11:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cve_manager', '0002_alter_soft_tbl_soft_platform'),
    ]

    operations = [
        migrations.AlterField(
            model_name='soft_tbl',
            name='soft_name',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='soft_tbl',
            name='soft_platform',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='soft_tbl',
            name='soft_type',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='soft_tbl',
            name='soft_vendor',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='soft_tbl',
            name='soft_version',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='cvss3_score',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='cvss3_text',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='cvss_score',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='cvss_text',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='cwe_identifier',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='description',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='exploit_status',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='fix_status',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='identifier',
            field=models.CharField(unique=True),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='identifiers',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='name',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='other',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='severity',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='solution',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='sources',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='vul_class',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='vul_incident',
            field=models.CharField(),
        ),
        migrations.AlterField(
            model_name='vul_tbl',
            name='vul_status',
            field=models.CharField(),
        ),
    ]
