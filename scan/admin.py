from django.contrib import admin
from .models import *

admin.site.register(HeaderScan)
admin.site.register(PortScan)
admin.site.register(TechnologyDetection)
admin.site.register(SQLInjectionScan)
admin.site.register(XSSScan)
admin.site.register(OpenRedirectScan)
admin.site.register(SSTIScan)
admin.site.register(VulnerabilityScan)

# Register your models here.
