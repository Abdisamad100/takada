# Generated by Django 3.2.9 on 2021-12-03 09:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ship', '0010_boat_status'),
    ]

    operations = [
        migrations.AlterField(
            model_name='boat',
            name='date_time',
            field=models.DateTimeField(),
        ),
    ]