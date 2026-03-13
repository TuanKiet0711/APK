from django.contrib import admin
from .models import ApkAnalysis


@admin.register(ApkAnalysis)
class ApkAnalysisAdmin(admin.ModelAdmin):
    list_display  = ("filename", "package_name", "ahp_verdict", "ahp_combined",
                     "ml_probability", "ml_is_malware", "analyzed_at")
    list_filter   = ("ahp_verdict", "ml_is_malware")
    search_fields = ("filename", "package_name")
    readonly_fields = ("full_result", "analyzed_at")
    ordering      = ("-analyzed_at",)
