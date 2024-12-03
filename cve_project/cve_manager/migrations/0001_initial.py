# Generated by Django 5.0.7 on 2024-11-23 09:42

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Vul_tbl',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('identifier', models.CharField(max_length=20, unique=True)),
                ('name', models.CharField(max_length=200)),
                ('description', models.CharField(max_length=200)),
                ('cwe_identifier', models.CharField(max_length=200)),
                ('identify_date', models.DateField()),
                ('cvss_score', models.CharField(max_length=200)),
                ('cvss_text', models.CharField(max_length=200)),
                ('cvss3_score', models.CharField(max_length=200)),
                ('cvss3_text', models.CharField(max_length=200)),
                ('severity', models.CharField(max_length=200)),
                ('solution', models.CharField(max_length=200)),
                ('vul_status', models.CharField(max_length=200)),
                ('exploit_status', models.CharField(max_length=200)),
                ('fix_status', models.CharField(max_length=200)),
                ('sources', models.CharField(max_length=200)),
                ('identifiers', models.CharField(max_length=200)),
                ('other', models.CharField(max_length=200)),
                ('vul_incident', models.CharField(max_length=200)),
                ('vul_class', models.CharField(max_length=200)),
            ],
            options={
                'db_table': 'cve_tbl_rez',
                'ordering': ('-id',),
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Soft_tbl',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('soft_vendor', models.CharField(max_length=200)),
                ('soft_name', models.CharField(max_length=200)),
                ('soft_version', models.CharField(max_length=200)),
                ('soft_platform', models.DateField()),
                ('soft_type', models.CharField(max_length=200)),
                ('identifier', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='cve_manager.vul_tbl', to_field='identifier')),
            ],
            options={
                'db_table': 'soft_tbl_rez',
                'ordering': ('-id',),
                'managed': True,
            },
        ),
    ]