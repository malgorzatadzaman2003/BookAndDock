from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from .models import Guide, Comment

class GuideForm(forms.ModelForm):
    class Meta:
        model = Guide
        fields = ['title', 'image', 'description', 'tips', 'category']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
            'tips': forms.Textarea(attrs={'rows': 6}),
        }
        status = forms.ChoiceField(choices=Guide.STATUS_CHOICES, initial='draft')

class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = [ 'content']
        widgets = {
            'content': forms.Textarea(attrs={'rows': 3}),
        }

    def clean_content(self):
        content = self.cleaned_data['content']
        if len(content) < 3:
            raise ValidationError('Content is too short.')
        return content


class SearchForm(forms.Form):
    query = forms.CharField(label='', validators=[MinLengthValidator(1)], max_length=100, required=False,
                            widget=forms.TextInput(attrs={'placeholder': '🔍 Search guides/articles'}))

class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already in use.")
        return email