from django.db import models


class ApkAnalysis(models.Model):
    """Stores one APK analysis result for history & statistics."""

    # --- File metadata ---
    filename     = models.CharField(max_length=255)
    package_name = models.CharField(max_length=255, blank=True, default="")
    version_name = models.CharField(max_length=100, blank=True, default="")
    analyzed_at  = models.DateTimeField(auto_now_add=True)

    # --- ML result ---
    ml_label          = models.CharField(max_length=10, blank=True, default="")
    ml_is_malware     = models.BooleanField(null=True)
    ml_probability    = models.FloatField(null=True)
    ml_score          = models.FloatField(null=True)
    ml_features_matched = models.IntegerField(null=True)

    # --- AHP ---
    ahp_score    = models.FloatField(null=True)   # weighted subscore 0–1
    ahp_combined = models.FloatField(null=True)   # final combined 0–1
    ahp_verdict  = models.CharField(max_length=30, blank=True, default="")
    s_c1 = models.FloatField(null=True)
    s_c2 = models.FloatField(null=True)
    s_c3 = models.FloatField(null=True)
    s_c4 = models.FloatField(null=True)
    n_c1 = models.IntegerField(null=True)
    n_c2 = models.IntegerField(null=True)
    n_c3 = models.IntegerField(null=True)
    n_c4 = models.IntegerField(null=True)

    # --- Full JSON (for later inspection) ---
    full_result = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ["-analyzed_at"]

    def __str__(self):
        return f"{self.filename} | {self.ahp_verdict} | {self.analyzed_at:%Y-%m-%d %H:%M}"
