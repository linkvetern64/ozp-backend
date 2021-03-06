# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2018-05-02 18:06
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
import ozpcenter.utils


class Migration(migrations.Migration):

    dependencies = [
        ('ozpcenter', '0040_profile_only_508_search_flag'),
    ]

    operations = [
        migrations.CreateModel(
            name='ListingVisitCount',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('count', models.PositiveIntegerField(default=0)),
                ('last_visit_date', models.DateTimeField(default=ozpcenter.utils.get_now_utc)),
                ('listing', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='listing_visit_counts', to='ozpcenter.Listing')),
                ('profile', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='listing_visit_counts', to='ozpcenter.Profile')),
            ],
        ),
    ]
