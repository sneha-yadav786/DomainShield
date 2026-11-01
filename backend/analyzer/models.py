from django.db import models


class Scan(models.Model):

    url = models.URLField(max_length=2048)

    domain = models.CharField(max_length=255)

    status = models.CharField(max_length=20)

    risk_score = models.IntegerField()

    confidence = models.FloatField(default=0.0)

    reasons = models.JSONField(default=list)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.domain} - {self.status}"