from django.contrib import admin

from BookAndDock.models import Guide, Comment

# Register your models here.
admin.site.register(Guide)
admin.site.register(Comment)