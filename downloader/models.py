from django.db import models
from django.contrib.auth.models import User

class DownloadedVideo(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="downloads")
    title = models.CharField(max_length=255)
    url = models.URLField()
    thumbnail_url = models.URLField(blank=True, null=True)
    format_id = models.CharField(max_length=50)
    downloaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} ({self.user.username})"