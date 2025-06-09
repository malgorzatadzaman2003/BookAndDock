from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm

from .models import Guide, Comment

class GuideForm(forms.ModelForm):
    links = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 6}),
        help_text="Enter one or more URLs, separated by commas or newlines."
    )

    class Meta:
        model = Guide
        fields = ['title', 'image', 'description', 'links', 'category', 'status']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
            'links': forms.Textarea(attrs={'rows': 6}),
            'status': forms.Select(),
        }

    def clean_links(self):
        data = self.cleaned_data.get('links', '')
        # Split on commas or newlines, strip spaces, filter out empties
        links_list = [link.strip() for link in data.replace(',', '\n').split('\n') if link.strip()]
        return links_list

class ArticleForm(forms.ModelForm):
    class Meta:
        model = Guide
        fields = ['title', 'image', 'description', 'category']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
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
                            widget=forms.TextInput(attrs={'placeholder': '🔍 Search'}))

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

class CustomLoginForm(AuthenticationForm):
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={"autofocus": True})
    )
    password = forms.CharField(label="Password", widget=forms.PasswordInput(attrs={'class': 'form-control'}))

class EmailOnlyLoginForm(forms.Form):
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={"autofocus": True})
    )