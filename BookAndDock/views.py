import json
import requests

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
from django.http import HttpResponseForbidden, HttpResponseRedirect, JsonResponse, HttpResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.contrib.auth import login as auth_login
from datetime import datetime


from BookDock import settings
from .serializers import GuideSerializer
from .models import Guide, Dock, DockSpace
from .forms import GuideForm, CommentForm, SearchForm, RegisterForm, EmailOnlyLoginForm, ArticleForm, CustomLoginForm


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

@login_required
def add_guide(request):
    if request.method == 'POST':
        form = GuideForm(request.POST, request.FILES)
        if form.is_valid():
            guide = form.save(commit=False)
            guide.created_by = request.user
            guide.status = request.POST.get('status', 'DRAFT').upper()  # e.g., DRAFT, BACKLOG, PUBLISHED
            guide.save()
            form.save_m2m()

            publication_date = datetime.now().replace(microsecond=0).isoformat()

            # Prepare JSON for external API
            api_payload = {
                "title": guide.title,
                "content": guide.description,
                "authorId": request.user.id,  # assuming it matches external authorId
                "publicationDate": publication_date,  # adjust if field differs
                "images": [request.build_absolute_uri(guide.image.url)] if guide.image else [],
                "links": [],   # Add logic if you have links field
                "guideStatus": guide.status.upper(),
                "guideCategory": guide.category.upper()
            }

            print(json.dumps(api_payload, indent=2))

            try:
                response = requests.post("http://localhost:8080/guides", json=api_payload)
                print(response.text)
                if response.status_code in [200, 201]:
                    print("Guide synced to API successfully.")
                else:
                    print(f"API sync failed. Status: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Error syncing guide to API: {e}")

            return redirect('profile_guides')
    else:
        form = GuideForm()

    return render(request, 'editor-guide/add_guide.html', {'form': form})

def add_article(request):
    if request.method == 'POST':
        form = ArticleForm(request.POST, request.FILES)
        if form.is_valid():
            guide = form.save(commit=False)
            guide.created_by = request.user
            guide.status = request.POST.get('status', 'draft')
            guide.save()
            form.save_m2m()
            return redirect('profile_articles')  # Redirect to the recipes list
    else:
        form = ArticleForm()
    return render(request, 'editor-guide/add_article.html', {'form': form})

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

@login_required
def docks(request):
    try:
        response = requests.get('http://localhost:8080/ports')
        docks = response.json() if response.status_code == 200 else []
    except requests.exceptions.RequestException:
        docks = []

    # Split docks into two lists
    published_docks = [dock for dock in docks if dock['approved']]
    docks_to_be_accepted = [dock for dock in docks if not dock['approved']]

    return render(request, 'profile_docks.html', {
        'published_docks': published_docks,
        'docks_to_be_accepted': docks_to_be_accepted,
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
    success_url = reverse_lazy('home')

    def form_valid(self, form):
        email = form.cleaned_data['email']
        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:

            user = User.objects.create_user(username=email, email=email)

        auth_login(self.request, user)
        return HttpResponseRedirect(self.get_success_url())

class LoginEditorView(FormView):
    form_class = EmailOnlyLoginForm
    template_name = "registration/login.html"  # your HTML file
    success_url = reverse_lazy('home')

    def form_valid(self, form):
        email = form.cleaned_data['email']
        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:

            user = User.objects.create_user(username=email, email=email)

        auth_login(self.request, user)
        return HttpResponseRedirect(self.get_success_url())

@csrf_exempt
def custom_login(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)

            username = data.get('username')
            email = data.get('email')
            first_name = data.get('name', '')
            last_name = data.get('surname', '')
            phone = data.get('phoneNumber', '')
            role = data.get('role')

            if username and email:
                user, created = User.objects.get_or_create(
                    username=username,
                    defaults={
                        'email': email,
                        'first_name': first_name,
                        'last_name': last_name
                    }
                )
                login(request, user)

                request.session['role'] = role

                return JsonResponse({"message": "Logged in successfully"})

            return JsonResponse({"error": "Missing username or email"}, status=400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid method"}, status=400)

@csrf_exempt
def custom_login_editor(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)

            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            first_name = data.get('name', '')
            last_name = data.get('surname', '')
            phone = data.get('phoneNumber', '')
            role = data.get('role')

            user = authenticate(request, username=data.get('username'), email=data.get('email'),
                                password=data.get('password'))

            if username and email:
                user, created = User.objects.get_or_create(
                    username=username,
                    password=password,
                    defaults={
                        'email': email,
                        'first_name': first_name,
                        'last_name': last_name
                    }
                )
                login(request, user)

                request.session['role'] = role

                return JsonResponse({"message": "Logged in successfully"})

            return JsonResponse({"error": "Missing username or email"}, status=400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid method"}, status=400)


@login_required
def accept_dock(request, dock_id):
    try:
        get_response = requests.get(f'http://localhost:8080/ports/{dock_id}')
        if get_response.status_code == 200:
            dock_data = get_response.json()

            dock_data['is_approved'] = True

            put_response = requests.put(
                f'http://localhost:8080/ports/{dock_id}/approve',
                json=dock_data
            )

            if put_response.status_code in [200, 204]:
                print("Dock approved successfully!")
            else:
                print("Failed to approve dock.")
        else:
            print("Failed to fetch dock data.")

    except requests.exceptions.RequestException as e:
        print(f"Error approving dock: {e}")

    return redirect('docks')

@login_required
def delete_dock(request, dock_id):
    try:
        response = requests.delete(f'http://localhost:8080/ports/{dock_id}')
        if response.status_code in [200, 204]:
            return redirect('docks')
        else:
            return HttpResponse("Failed to delete dock on backend", status=response.status_code)
    except requests.exceptions.RequestException as e:
        return HttpResponse(f"Error: {e}", status=500)

@login_required
def dock_detail(request, dock_id):
    try:
        # Fetch dock details from backend
        dock_response = requests.get(f'http://localhost:8080/ports/{dock_id}')
        if dock_response.status_code != 200:
            return HttpResponse("Failed to retrieve dock details", status=dock_response.status_code)
        dock = dock_response.json()

        # (Optional placeholder - no dock spaces API yet)
        dock_spaces = []  # Later fetch from /docking-spots/ when available

        return render(request, 'dock_detail.html', {
            'dock': dock,
            'dock_spaces': dock_spaces
        })
    except requests.exceptions.RequestException as e:
        return HttpResponse(f"Error: {e}", status=500)

@login_required
def add_dock_space(request, dock_id):
    dock = get_object_or_404(Dock, pk=dock_id)

    if request.method == 'POST':
        name = request.POST.get('name')
        length = request.POST.get('length')
        width = request.POST.get('width')
        price = request.POST.get('price')

        DockSpace.objects.create(
            dock=dock,
            name=name,
            length=length,
            width=width,
            price_per_day=price
        )
        return redirect('dock_detail', dock_id=dock.pk)

    return render(request, 'add_dock_space.html', {'dock': dock})

@login_required
def delete_dock_space(request, space_id):
    space = get_object_or_404(DockSpace, pk=space_id)
    dock_id = space.dock.pk
    space.delete()
    return redirect('dock_detail', dock_id=dock_id)

@login_required
def manage_guides(request):
    try:
        response = requests.get('http://localhost:8080/guides')
        guides = response.json() if response.status_code == 200 else []
    except requests.exceptions.RequestException:
        guides = []

    published_guides = [g for g in guides if g.get('approved')]
    unpublished_guides = [g for g in guides if not g.get('approved')]

    return render(request, 'profile_guides.html', {
        'published_guides': published_guides,
        'unpublished_guides': unpublished_guides,
    })

@login_required
def accept_guide(request, guide_id):
    try:
        # Get existing guide data
        response = requests.get(f'http://localhost:8080/guides/{guide_id}')
        if response.status_code != 200:
            return HttpResponse("Guide not found", status=response.status_code)
        guide_data = response.json()

        # Set approved to true
        guide_data['approved'] = True

        # Send updated data back
        put_response = requests.put(
            f'http://localhost:8080/guides/{guide_id}',
            json=guide_data
        )
        if put_response.status_code in [200, 204]:
            return redirect('manage_guides')
        return HttpResponse("Failed to approve guide", status=put_response.status_code)
    except requests.exceptions.RequestException as e:
        return HttpResponse(f"Error: {e}", status=500)

@login_required
def delete_guide(request, guide_id):
    try:
        response = requests.delete(f'http://localhost:8080/guides/{guide_id}')
        if response.status_code in [200, 204]:
            return redirect('manage_guides')
        return HttpResponse("Failed to delete guide", status=response.status_code)
    except requests.exceptions.RequestException as e:
        return HttpResponse(f"Error: {e}", status=500)

@login_required
def guide_detail(request, guide_id):
    try:
        response = requests.get(f'http://localhost:8080/guides/{guide_id}')
        if response.status_code != 200:
            return HttpResponse("Guide not found", status=response.status_code)
        guide = response.json()
        return render(request, 'guide_detail_admin.html', {'guide': guide})
    except requests.exceptions.RequestException as e:
        return HttpResponse(f"Error: {e}", status=500)

@login_required
def users(request):
    try:
        response = requests.get('http://localhost:8080/users/users')
        users = response.json() if response.status_code == 200 else []
    except requests.exceptions.RequestException as e:
        return HttpResponse(f"Error fetching users: {e}", status=500)

    return render(request, 'admin_users.html', {'users': users})

@login_required
def ban_user(request, user_email):
    try:
        response = requests.delete(
            'http://localhost:8080/users',
            json={"email": user_email}
        )
        if response.status_code in [200, 204]:
            return redirect('users')
        return HttpResponse("Failed to ban user", status=response.status_code)
    except requests.exceptions.RequestException as e:
        return HttpResponse(f"Error banning user: {e}", status=500)

@login_required
def user_detail(request, user_id):
    try:
        response = requests.get(f'http://localhost:8080/users/users/{user_id}')
        if response.status_code != 200:
            return HttpResponse("User not found", status=response.status_code)
        user = response.json()
        return render(request, 'user_detail.html', {'user': user})
    except requests.exceptions.RequestException as e:
        return HttpResponse(f"Error fetching user: {e}", status=500)

