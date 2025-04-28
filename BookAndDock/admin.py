from django.contrib import admin

from BookAndDock.models import Guide, Comment, Dock

# Register your models here.
admin.site.register(Guide)
admin.site.register(Comment)
admin.site.register(Dock)