from django.contrib import admin
from .models import CustomUser

admin.register(CustomUser)


class UserAdmin(admin.ModelAdmin):
    list_display = ['email', 'phone_number', 'last_name', 'first_name', 'date_of_birth',
                    'created_at'
                    ]


ordering = ('email',)

admin.site.register(CustomUser, UserAdmin)
