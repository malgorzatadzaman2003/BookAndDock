from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from .views import delete_account


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

# API Endpoint for Guides
    path('api/guides/', views.api_guides, name='api_guides'),
]
