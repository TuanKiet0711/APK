from django.urls import path

from . import views

urlpatterns = [
    path("analyze/",  views.analyze_apk, name="analyze_apk"),
    path("stats/",    views.stats,       name="stats"),
    path("ahp-info/", views.ahp_info,    name="ahp_info"),
]
