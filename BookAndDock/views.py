from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import RedirectURLMixin
from django.shortcuts import render, redirect, get_object_or_404, resolve_url
from django.contrib.auth.decorators import login_required, login_not_required
from django.contrib.auth import logout, authenticate, login, get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.contrib.auth import login as auth_login


from BookDock import settings
from .serializers import GuideSerializer
from .models import Guide
from .forms import GuideForm, CommentForm, SearchForm, RegisterForm, EmailOnlyLoginForm


def home(request):
    guides = Guide.objects.filter(status='published')
    form = SearchForm(request.GET)

    if form.is_valid() and form.cleaned_data['query']:
        query = form.cleaned_data['query']
        if query:
            guides = guides.filter(title__icontains=query)

    return render(request, 'home.html', {'guides': guides, 'form': form})

def about_view(request):
    return render(request, 'about.html')

@login_required
def account_view(request):
    return render(request, 'account.html')

def guide_detail(request, pk):
    guide = get_object_or_404(Guide, pk=pk)

    tips = guide.tips.split('\n') if guide.tips else []

    comments = guide.comment_set.order_by('-created_at')  # Fetch comments for the recipe
    form = CommentForm()  # Empty form for new comment submission
    return render(request, 'editor-guide/guide_detail.html', {
        'guide': guide,
        'tips': tips,
        'comments': comments,
        'form': form})

def add_guide(request):
    if request.method == 'POST':
        form = GuideForm(request.POST, request.FILES)
        if form.is_valid():
            guide = form.save(commit=False)
            guide.created_by = request.user
            guide.status = request.POST.get('status', 'draft')
            guide.save()
            form.save_m2m()
            return redirect('profile_guides')  # Redirect to the recipes list
    else:
        form = GuideForm()
    return render(request, 'editor-guide/add_guide.html', {'form': form})

@login_required
def modify_guide(request, pk):
    guide = get_object_or_404(Guide, pk=pk)

    if request.method == 'POST':
        form = GuideForm(request.POST, request.FILES, instance=guide)
        if form.is_valid():
            guide.status = request.POST.get('status', 'draft')
            form.save()
            return redirect('profile_guides')  # Redirect back to profile page after saving the modifications
    else:
        form = GuideForm(instance=guide)

    return render(request, 'editor-guide/modify_guide.html', {'form': form, 'guide': guide})

@login_required
def delete_guide(request, pk):
    guide = get_object_or_404(Guide, pk=pk)
    # Ensure only the creator can delete the recipe
    if guide.created_by != request.user:
        return HttpResponseForbidden("You are not allowed to delete this guide.")

    if request.method == 'POST':
        guide.delete()
        return redirect('profile_guides')  # Redirect to the profile page after deletion

    return render(request, 'editor-guide/delete_guide.html', {'guide': guide})

from django.shortcuts import redirect

def post_comment(request, pk):
    guide = get_object_or_404(Guide, id=pk)

    if request.method == 'POST':
        form = CommentForm(request.POST)
        if form.is_valid():
            comment = form.save(commit=False)
            comment.guide = guide
            comment.author = request.user  # Associate the logged-in user

            parent_id = request.POST.get('parent_id')
            if parent_id:
                comment.parent_id = parent_id

            comment.save()
            return redirect('guide_detail', pk=pk)  # Redirect to recipe detail
        else:
            comments = guide.comment_set.order_by('-created_at')
            context = {'guide': guide, 'comments': comments, 'form': form}
            return render(request, 'editor-guide/guide_detail.html', context)
    else:
        return redirect('guide_detail', pk=pk)

@login_required
def profile_guides(request):
    published_guides = Guide.objects.filter(created_by=request.user, status='published', category='guide')
    unpublished_guides = Guide.objects.filter(created_by=request.user, status='draft', category='guide')
    return render(request, 'profile_guides.html', {
        'published_guides': published_guides,
        'unpublished_guides': unpublished_guides
    })

@login_required
def profile_articles(request):
    published_articles = Guide.objects.filter(created_by=request.user, status='published', category='article')
    unpublished_articles = Guide.objects.filter(created_by=request.user, status='draft', category='article')
    return render(request, 'profile_articles.html', {
        'published_articles': published_articles,
        'unpublished_articles': unpublished_articles
    })

def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')

            # Ensure email is unique
            if User.objects.filter(email=email).exists():
                return render(request, 'registration/register.html', {"form": form, "error": "Email already in use."})

            user = form.save(commit=False)
            user.is_active = False  # Deactivate account until email confirmed
            user.save()

            # Send activation email
            current_site = get_current_site(request)
            subject = 'Activate Your Account'
            message = render_to_string('registration/activation/activation_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            send_mail(subject, message, 'bookdock_blog@neverland.com', [email])

            return render(request, 'registration/activation/activation_sent.html')
    else:
        form = RegisterForm()
    return render(request, 'registration/register.html', {'form': form})

def custom_logout(request):
    logout(request)
    return redirect('home')

@api_view(['GET'])
def api_guides(request):
    guides = Guide.objects.all()
    serializer = GuideSerializer(guides, many=True)
    return Response(serializer.data)

def activate(request, uid, token):
    try:
        uid = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return redirect('login')
    else:
        return render(request, 'registration/register.html')

@login_required
def delete_account(request):
    user = request.user
    user.delete()
    logout(request)
    return redirect('home')


class LoginAdminView(FormView):
    form_class = EmailOnlyLoginForm
    template_name = "registration/login_admin.html"  # your HTML file
    success_url = reverse_lazy('home')  # or whatever page you want to go after login

    def form_valid(self, form):
        email = form.cleaned_data['email']
        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Optional: create user if not found, or redirect/fail silently
            user = User.objects.create_user(username=email, email=email)

        auth_login(self.request, user)
        return HttpResponseRedirect(self.get_success_url())