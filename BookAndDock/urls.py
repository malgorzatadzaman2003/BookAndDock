from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from .views import delete_account, LoginEditorView
from .forms import CustomLoginForm

urlpatterns = [
    path('', views.home, name='home'),
    path('guide/<int:guide_id>/', views.guide_detail, name='guide_detail'),
    path('editor/guide/<int:guide_id>/', views.guide_detail_editor, name='guide_detail_editor'),
    path('add/', views.add_guide, name='add_guide'),
    path('recipe/<int:pk>/comment', views.post_comment, name='post_comment'),
    path('profile_guides/', views.profile_guides, name='profile_guides'),
    path('profile_articles/', views.profile_articles, name='profile_articles'),
    path('register/', views.register, name='register'),
    path('recipe/<int:pk>/delete/', views.delete_guide, name='delete_guide'),
    path('guide/<int:guide_id>/delete/', views.delete_guide_editor, name='delete_guide_editor'),
    path('recipe/<int:pk>/modify_guide/', views.modify_guide, name='modify_guide'),
    path('login_editor/', LoginEditorView.as_view(), name='login'),
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
    path('custom_login_editor/', views.custom_login_editor, name='custom_login_editor'),
    path('profile_docks/', views.docks, name='docks'),
    path('accept_dock/<int:dock_id>/', views.accept_dock, name='accept_dock'),
    path('delete_dock/<int:dock_id>/', views.delete_dock, name='delete_dock'),
    path('dock/<int:dock_id>/', views.dock_detail, name='dock_detail'),
    path('dock/<int:dock_id>/add_space/', views.add_dock_space, name='add_dock_space'),
    path('dock_space/<int:space_id>/delete/', views.delete_dock_space, name='delete_dock_space'),
    path('guides_manage/', views.manage_guides, name='manage_guides'),
    path('guide/<int:guide_id>/', views.guide_detail, name='guide_detail'),
    path('guide/<int:guide_id>/accept/', views.accept_guide, name='accept_guide'),
    path('guide/<int:guide_id>/delete/', views.delete_guide, name='delete_guide'),
    path('admin-panel/users/', views.users, name='users'),
    path('admin-panel/users/<int:user_id>/', views.user_detail, name='user_detail'),
    path('admin-panel/users/<str:user_email>/ban/', views.ban_user, name='ban_user'),
    path('admin-panel/bookings/', views.bookings, name='bookings'),
    path('admin-panel/bookings/<int:booking_id>/', views.booking_detail, name='booking_detail'),
    path('admin-panel/users/<int:user_id>/', views.user_detail, name='user_detail'),


# API Endpoint for Guides
    path('api/guides/', views.api_guides, name='api_guides'),
]
