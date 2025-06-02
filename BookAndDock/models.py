from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinLengthValidator, RegexValidator
from django.utils import timezone

class Guide(models.Model):
    STATUS_CHOICES = [
        ('draft', 'Draft'),  # Unpublished
        ('published', 'Published'),  # Published
    ]

    CATEGORY_CHOICES = [
        ('guide', 'Guide'),
        ('article', 'Article'),
    ]

    title = models.CharField(max_length=255)
    image = models.ImageField(upload_to='guides_images/', blank=True, null=True)
    description = models.TextField()
    tips = models.TextField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='draft')
    category = models.CharField(max_length=10, choices=CATEGORY_CHOICES, default='guide')

    def __str__(self):
        return self.title

class Comment(models.Model):
    guide = models.ForeignKey(Guide, on_delete=models.CASCADE)
    author = models.CharField(max_length=31, validators=[MinLengthValidator(3), RegexValidator(r'^[A-Z][a-zA-Z ]+$', message='Author name must start with a capital letter.')])
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    parent = models.ForeignKey('self', null=True, blank=True, related_name='replies', on_delete=models.CASCADE)

    def __str__(self):
        return f"Comment by {self.author}"



class Dock(models.Model):
    STATUS_CHOICES = [
        ('published', 'Published'),
        ('pending', 'Pending'),
    ]

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    location = models.CharField(max_length=255, blank=True)
    image = models.ImageField(upload_to='docks/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    def __str__(self):
        return self.name

class DockSpace(models.Model):
    dock = models.ForeignKey('Dock', on_delete=models.CASCADE, related_name='spaces')
    name = models.CharField(max_length=255)
    length = models.FloatField(help_text="Length of the dock space (in meters)")
    width = models.FloatField(help_text="Width of the dock space (in meters)")
    price_per_day = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f"{self.name} ({self.dock.name})"
