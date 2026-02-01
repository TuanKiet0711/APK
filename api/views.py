import json
import subprocess
import sys
import tempfile
from pathlib import Path

from django.http import HttpResponseBadRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def analyze_apk(request):
    if request.method != "POST":
        return HttpResponseBadRequest("POST only")

    if "apk" not in request.FILES:
        return HttpResponseBadRequest("Missing file field: apk")

    apk_file = request.FILES["apk"]

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        apk_path = tmpdir_path / apk_file.name
        with apk_path.open("wb") as f:
            for chunk in apk_file.chunks():
                f.write(chunk)

        out_json = tmpdir_path / "out.json"
        analyzer_path = Path(__file__).resolve().parent.parent / "apk_analyzer.py"
        cmd = [
            sys.executable,
            str(analyzer_path),
            str(apk_path),
            str(out_json),
            "--fast",
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            return JsonResponse(
                {"error": "analyzer_failed", "stderr": exc.stderr, "stdout": exc.stdout},
                status=500,
            )

        data = json.loads(out_json.read_text(encoding="utf-8"))
        return JsonResponse(data, json_dumps_params={"ensure_ascii": True, "indent": 2})
