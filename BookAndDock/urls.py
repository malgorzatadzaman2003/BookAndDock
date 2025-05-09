from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from .views import delete_account
from .forms import CustomLoginForm

urlpatterns = [
    path('', views.home, name='home'),
    path('guide/<int:pk>/', views.guide_detail, name='guide_detail'),
    path('add/', views.add_guide, name='add_guide'),
    path('recipe/<int:pk>/comment', views.post_comment, name='post_comment'),
    path('profile_guides/', views.profile_guides, name='profile_guides'),
    path('profile_articles/', views.profile_articles, name='profile_articles'),
    path('register/', views.register, name='register'),
    path('recipe/<int:pk>/delete/', views.delete_guide, name='delete_guide'),
    path('recipe/<int:pk>/modify_guide/', views.modify_guide, name='modify_guide'),
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html', authentication_form=CustomLoginForm), name='login'),
    path('logout/', views.custom_logout, name='logout'),
    path('about/', views.about_view, name='about'),
    path('account/', views.account_view, name='account'),
    path('register/', views.register, name='register'),
    path('activate/<uid>/<token>/', views.activate, name='activate'),
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='registration/password_reset/password_reset.html'), name='password_reset'),
    path('password_reset_done/', auth_views.PasswordResetDoneView.as_view(template_name='registration/password_reset/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='registration//password_reset/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='registration//password_reset/password_reset_complete.html'), name='password_reset_complete'),
    path('delete_account/', delete_account, name='delete_account'),
    path("login_admin/", views.LoginAdminView.as_view(), name="login_admin"),
    path('custom_login/', views.custom_login, name='custom_login'),
    path('profile_docks/', views.docks, name='docks'),
    path('accept_dock/<int:dock_id>/', views.accept_dock, name='accept_dock'),
    path('delete_dock/<int:dock_id>/', views.delete_dock, name='delete_dock'),
    path('dock/<int:dock_id>/', views.dock_detail, name='dock_detail'),
    path('dock/<int:dock_id>/add_space/', views.add_dock_space, name='add_dock_space'),
    path('dock_space/<int:space_id>/delete/', views.delete_dock_space, name='delete_dock_space'),

# API Endpoint for Guides
    path('api/guides/', views.api_guides, name='api_guides'),
]
