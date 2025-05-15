from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# Create your models here.

class HeaderScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)        
    url = models.URLField() 
    grade = models.CharField(max_length=1)
    score = models.IntegerField()
    report = models.JSONField()
    created_on = models.DateTimeField(auto_now_add=True)
    

    def __str__(self):
        return self.user.username



class PortScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)        
    target_ip = models.GenericIPAddressField()
    ports = models.JSONField() 
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.target_ip}"




class TechnologyDetection(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField()
    tech = models.JSONField()
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.url}"
    

class SQLInjectionScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField()
    results = models.JSONField()  # To store payloads and their results
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.url} - {self.created_on.strftime('%Y-%m-%d %H:%M:%S')}"
    

class XSSScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField()
    results = models.JSONField()  # To store payloads and their results
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.url} - {self.created_on.strftime('%Y-%m-%d %H:%M:%S')}"


class OpenRedirectScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField()
    results = models.JSONField()  # To store payloads and their results
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.url} - {self.created_on.strftime('%Y-%m-%d %H:%M:%S')}"
    

class SSTIScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField()
    results = models.JSONField()  # To store payloads and their results
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.url} - {self.created_on.strftime('%Y-%m-%d %H:%M:%S')}"
    

class VulnerabilityScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField()
    results = models.JSONField()  
    created_on = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.url} - {self.created_on.strftime('%Y-%m-%d %H:%M:%S')}"