from django.urls import path
from .views import *

urlpatterns = [
    path('',loginuser,name='login'),
    path('header/', security_scan_view, name='header'), 
    path('port/', port_scan, name='port'),
    path('tech/', technology_detection, name='tech'),
    path('sqli/',sql_injection_scan, name='sqli'),
    path('xss/',xss_scan, name='xss'),
    path('open/',open_redirect_scan, name='open'),
    path('ssti/',ssti_scan, name='ssti'),
    path('multi_scan/', multi_scan, name='multi_scan'),
    
   
]