# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2018-05-31 17:04
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ozpcenter', '0042_profile_theme'),
    ]

    operations = [
        migrations.CreateModel(
            name='WorkRole',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=30, unique=True)),
            ],
        ),
        migrations.AddField(
            model_name='profile',
            name='work_roles',
            field=models.ManyToManyField(db_table='work_role_profile', related_name='profiles', to='ozpcenter.WorkRole'),
        ),
    ]
