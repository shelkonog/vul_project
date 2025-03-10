# Generated by Django 5.1.6 on 2025-02-26 17:19

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Measure',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('id_sec_measure', models.CharField(unique=True)),
                ('sec_measure', models.CharField()),
                ('sub_gr_measure', models.CharField()),
                ('gr_measure', models.CharField()),
            ],
            options={
                'db_table': 'sec_measure_tbl',
                'ordering': ('-id',),
                'managed': True,
            },
        ),
    ]
