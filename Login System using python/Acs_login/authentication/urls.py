from django.contrib import admin
from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.index, name = "index" ),
    path('loginpage', views.loginpage, name = "loginpage"),
    path('home', views.home, name = "home"),
    path('register', views.register, name = "register"),
    path('loggedout', views.loggedout, name = "loggedout"),
    path('about', views.about, name = "about"),
    path('confirm', views.confirm, name = "confirm"),
    path('reset_link', views.reset_link, name = "reset_link"),
    path('activate/<uidb64>/<token>', views.activate , name="activate"),
    path('reset_form', views.reset_form , name="reset_form"),
    path('password_reset_confirm/<uidb64>/<token>', views.password_reset_confirm , name="password_reset_confirm"),
    path('password_reset_complete', views.password_reset_complete , name="password_reset_complete"),
    
]
