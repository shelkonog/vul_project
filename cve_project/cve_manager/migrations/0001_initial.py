# Generated by Django 5.0.7 on 2024-07-15 16:47

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
                ('identifier', models.CharField(max_length=20)),
                ('name', models.CharField(max_length=200)),
            ],
            options={
                'db_table': 'cve_tbl_rez',
                'managed': False,
            },
        ),
    ]
