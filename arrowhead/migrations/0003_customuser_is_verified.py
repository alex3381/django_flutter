# Generated by Django 3.2.7 on 2021-09-12 16:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('arrowhead', '0002_customuser_auth_provider'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='is_verified',
            field=models.BooleanField(default=False),
        ),
    ]