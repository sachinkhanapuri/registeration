from django.urls import path
from registeration import views

urlpatterns = [
    path('', views.HomeView.as_view(), name='home'),
    path('register/', views.RegisterationView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('activate/<uidb64>/<token>',views.VerificationView.as_view(),name='activate'),
    path('reset-password/',views.RequestResetLinkView.as_view(),name='reset-password'),
    path('change-password/<uidb64>/<token>',views.CompletePasswordChangeView.as_view(),name='change-password'),

]