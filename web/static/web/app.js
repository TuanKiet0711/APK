const form = document.getElementById("uploadForm");
const apkInput = document.getElementById("apkInput");
const fileName = document.getElementById("fileName");
const statusEl = document.getElementById("status");
const stats = {
  perms: document.getElementById("statPerms"),
  apis: document.getElementById("statApis"),
  strings: document.getElementById("statStrings"),
  net: document.getElementById("statNet"),
};
const metaEl = document.getElementById("meta");
const chipsEl = document.getElementById("chips");
const tabContent = document.getElementById("tabContent");
const tabs = document.querySelectorAll(".tab");
const riskScoreEl = document.getElementById("riskScore");
const riskVerdictEl = document.getElementById("riskVerdict");
const riskNotesEl = document.getElementById("riskNotes");
const riskReasonsEl = document.getElementById("riskReasons");
const riskAdviceEl = document.getElementById("riskAdvice");
const riskRulesEl = document.getElementById("riskRules");

let currentData = null;

document.querySelector(".file__btn").addEventListener("click", () => {
  apkInput.click();
});

apkInput.addEventListener("change", () => {
  const f = apkInput.files[0];
  fileName.textContent = f ? f.name : "No file selected";
});

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    renderTab(tab.dataset.tab);
  });
});

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = apkInput.files[0];
  if (!f) {
    statusEl.textContent = "Please choose an APK file.";
    return;
  }
  statusEl.textContent = "Analyzing... this may take a while.";

  const fd = new FormData();
  fd.append("apk", f);

  try {
    const res = await fetch("/api/analyze/", {
      method: "POST",
      body: fd,
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(errText || "API error");
    }
    const data = await res.json();
    currentData = data;
    statusEl.textContent = "Done.";
    renderAll(data);
  } catch (err) {
    statusEl.textContent = "Error: " + err.message;
  }
});


function renderAll(data) {

  const perms =
    (data.permissions?.requested?.length || 0) +
    (data.permissions?.declared?.length || 0);
  stats.perms.textContent = perms;
  stats.apis.textContent = data.api_calls?.length || 0;
  stats.strings.textContent = data.strings?.length || 0;
  const netCount =
    (data.network?.urls?.length || 0) +
    (data.network?.domains?.length || 0) +
    (data.network?.ips?.length || 0);
  stats.net.textContent = netCount;

  metaEl.innerHTML = "";
  const meta = data.metadata || {};
  const items = [
    ["Package", meta.package_name],
    ["Version", `${meta.version_name} (${meta.version_code})`],
    ["minSdk", meta.min_sdk],
    ["targetSdk", meta.target_sdk],
    ["Debuggable", meta.debuggable],
  ];
  items.forEach(([k, v]) => {
    const div = document.createElement("div");
    div.textContent = `${k}: ${v ?? "-"}`;
    metaEl.appendChild(div);
  });

  chipsEl.innerHTML = "";
  const indicators = [
    ...(data.network?.urls || []),
    ...(data.network?.domains || []),
    ...(data.network?.ips || []),
  ]
    .filter((x) => !String(x).includes("schemas.android.com"))
    .filter((x) => !String(x).includes("android.com"))
    .slice(0, 25);
  indicators.forEach((x) => {
    const chip = document.createElement("div");
    chip.className = "chip";
    chip.textContent = x;
    chipsEl.appendChild(chip);
  });

  renderRisk(data);
  renderTab(document.querySelector(".tab.active").dataset.tab);
}

function renderRisk(d) {
  const dangerPerms = new Set([
    "SEND_SMS",
    "READ_SMS",
    "RECEIVE_SMS",
    "WRITE_SMS",
    "READ_PHONE_STATE",
    "GET_ACCOUNTS",
    "READ_CONTACTS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES",
    "INSTALL_PACKAGES",
    "DELETE_PACKAGES",
    "REBOOT",
    "BIND_DEVICE_ADMIN",
    "DEVICE_ADMIN",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "RECORD_AUDIO",
  ]);

  const suspiciousApis = [
    "Runtime.exec",
    "ProcessBuilder",
    "DexClassLoader",
    "PathClassLoader",
    "defineClass",
    "System.loadLibrary",
    "Runtime.load",
    "Class.forName",
    "getDeclaredField",
    "getMethod",
    "getDeviceId",
    "getSubscriberId",
    "getLine1Number",
  ];

  const rawPerms = [
    ...(d.permissions?.requested || []),
    ...(d.permissions?.declared || []),
  ];
  const perms = normalizePerms(rawPerms);
  const apiSigs = new Set(
    (d.api_calls || []).map((c) => c.signature || `${c.class}.${c.name}`)
  );
  const exported = [
    ...(d.components?.activities || []),
    ...(d.components?.services || []),
    ...(d.components?.receivers || []),
    ...(d.components?.providers || []),
  ].filter((c) => c.exported === true);

  const intents = new Set();
  Object.values(d.components || {}).forEach((list) => {
    (list || []).forEach((c) => {
      const f = c.intent_filters || {};
      (f.actions || []).forEach((x) => intents.add(x));
      (f.categories || []).forEach((x) => intents.add(x));
      (f.data || []).forEach((x) => intents.add(x));
    });
  });

  let score = 0;
  const notes = [];
  const reasons = [];

  const hitPerms = [...dangerPerms].filter((p) => perms.has(p));
  if (hitPerms.length) {
    score += Math.min(40, hitPerms.length * 4);
    const sample = hitPerms.slice(0, 6).join(", ");
    notes.push(`Permissions nhạy cảm: ${sample}`);
    reasons.push(`Có ${hitPerms.length} quyền nhạy cảm (vd: ${sample})`);
  }

  const hitApis = suspiciousApis.filter((a) => {
    for (const sig of apiSigs) {
      if (String(sig).includes(a)) return true;
    }
    return false;
  });
  if (hitApis.length) {
    score += Math.min(35, hitApis.length * 5);
    const sample = hitApis.slice(0, 5).join(", ");
    notes.push(`API đáng ngờ: ${sample}`);
    reasons.push(`Dùng API nguy cơ cao (vd: ${sample})`);
  }

  if (exported.length) {
    score += Math.min(15, exported.length);
    reasons.push(`Có ${exported.length} component exported`);
  }

  const netCount =
    (d.network?.urls?.length || 0) +
    (d.network?.domains?.length || 0) +
    (d.network?.ips?.length || 0);
  if (netCount > 0) {
    score += Math.min(10, Math.ceil(netCount / 10));
    reasons.push(`Phát hiện ${netCount} chỉ dấu mạng (URL/domain/IP)`);
  }

  score = Math.min(100, score);
  riskScoreEl.textContent = score;

  riskVerdictEl.classList.remove("safe", "warn", "bad");
  riskAdviceEl.classList.remove("safe", "warn", "bad");
  if (score < 25) {
    riskVerdictEl.textContent = "Nguy cơ thấp";
    riskVerdictEl.classList.add("safe");
    riskAdviceEl.textContent =
      "Khuyến nghị: Có thể cài đặt, nhưng vẫn nên tải từ nguồn tin cậy.";
    riskAdviceEl.classList.add("safe");
  } else if (score < 55) {
    riskVerdictEl.textContent = "Nguy cơ trung bình";
    riskVerdictEl.classList.add("warn");
    riskAdviceEl.textContent =
      "Khuyến nghị: Cân nhắc trước khi cài đặt, kiểm tra quyền và nguồn tải.";
    riskAdviceEl.classList.add("warn");
  } else {
    riskVerdictEl.textContent = "Nguy cơ cao";
    riskVerdictEl.classList.add("bad");
    riskAdviceEl.textContent =
      "Khuyến nghị: Không nên cài đặt nếu không thực sự cần và không rõ nguồn gốc.";
    riskAdviceEl.classList.add("bad");
  }

  riskNotesEl.textContent =
    notes.length > 0
      ? notes.join(" | ")
      : "Không thấy dấu hiệu nhạy cảm nổi bật.";

  riskReasonsEl.innerHTML = "";
  (reasons.length ? reasons : ["Chưa có lý do nổi bật."]).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    riskReasonsEl.appendChild(li);
  });

  renderRuleAlerts({ perms, apiSigs, exported, netCount, intents });
}

function renderRuleAlerts(ctx) {
  const rules = [
    {
      id: "sms_combo",
      severity: "high",
      title: "Gửi/nhận SMS",
      when: () =>
        hasPerm(ctx.perms, "SEND_SMS") &&
        (hasPerm(ctx.perms, "RECEIVE_SMS") || hasPerm(ctx.perms, "READ_SMS")),
      message: "Có thể gửi SMS ngầm hoặc đọc tin nhắn.",
    },
    {
      id: "boot_background",
      severity: "medium",
      title: "Tự chạy sau khởi động",
      when: () =>
        hasPerm(ctx.perms, "RECEIVE_BOOT_COMPLETED") ||
        hasIntent(ctx.intents, "BOOT_COMPLETED"),
      message: "Có thể tự khởi chạy nền sau khi bật máy.",
    },
    {
      id: "dynamic_code",
      severity: "high",
      title: "Nạp code động",
      when: () =>
        hasApi(ctx.apiSigs, "DexClassLoader") ||
        hasApi(ctx.apiSigs, "PathClassLoader") ||
        hasApi(ctx.apiSigs, "defineClass"),
      message: "Có dấu hiệu nạp code động, khó kiểm soát hành vi.",
    },
    {
      id: "reflection",
      severity: "medium",
      title: "Reflection",
      when: () =>
        hasApi(ctx.apiSigs, "Class.forName") ||
        hasApi(ctx.apiSigs, "getDeclaredField") ||
        hasApi(ctx.apiSigs, "getMethod"),
      message: "Dùng reflection, có thể che giấu hành vi.",
    },
    {
      id: "device_id",
      severity: "medium",
      title: "Thu thập định danh",
      when: () =>
        hasApi(ctx.apiSigs, "getDeviceId") ||
        hasApi(ctx.apiSigs, "getSubscriberId") ||
        hasApi(ctx.apiSigs, "getLine1Number"),
      message: "Có thể thu thập định danh thiết bị/SIM.",
    },
    {
      id: "exported",
      severity: "low",
      title: "Component exported",
      when: () => ctx.exported.length >= 5,
      message: "Nhiều component exported có thể mở bề mặt tấn công.",
    },
    {
      id: "network_ioc",
      severity: "low",
      title: "Nhiều IOC mạng",
      when: () => ctx.netCount >= 20,
      message: "Nhiều domain/URL/IP có thể cần kiểm tra.",
    },
  ];

  riskRulesEl.innerHTML = "";
  const hits = rules.filter((r) => r.when());
  if (!hits.length) {
    if (riskRulesEl) {
      riskRulesEl.innerHTML = "<li>Không có cảnh báo rule đáng chú ý.</li>";
    }
    return;
  }

  hits.forEach((r) => {
    const li = document.createElement("li");
    const badge = document.createElement("span");
    badge.className = `rule ${r.severity}`;
    badge.textContent = r.severity.toUpperCase();
    li.innerHTML = `${r.title}: ${r.message}`;
    li.appendChild(badge);
    riskRulesEl.appendChild(li);
  });
}

function hasApi(apiSet, needle) {
  for (const sig of apiSet) {
    if (String(sig).includes(needle)) return true;
  }
  return false;
}

function normalizePerms(list) {
  const out = new Set();
  list.forEach((p) => {
    if (!p) return;
    const s = String(p);
    out.add(s);
    const lastDot = s.lastIndexOf(".");
    if (lastDot !== -1) out.add(s.slice(lastDot + 1));
    const lastSlash = s.lastIndexOf("/");
    if (lastSlash !== -1) out.add(s.slice(lastSlash + 1));
  });
  return out;
}

function hasPerm(set, key) {
  if (!set || !key) return false;
  if (set.has(key)) return true;
  for (const p of set) {
    if (String(p).endsWith("." + key)) return true;
    if (String(p).endsWith("/" + key)) return true;
  }
  return false;
}

function hasIntent(set, key) {
  if (!set || !key) return false;
  if (set.has(key)) return true;
  for (const v of set) {
    if (String(v).endsWith("." + key)) return true;
    if (String(v).endsWith("/" + key)) return true;
  }
  return false;
}

function renderTab(tab) {
  if (!currentData) {
    tabContent.innerHTML = "<p class='muted'>No data yet.</p>";
    return;
  }

  const d = currentData;
  if (tab === "permissions") {
    const groups = [
      {
        title: "SMS / Call",
        keys: ["SEND_SMS", "READ_SMS", "RECEIVE_SMS", "WRITE_SMS", "CALL_PHONE"],
      },
      {
        title: "Dữ liệu cá nhân",
        keys: ["READ_CONTACTS", "READ_CALL_LOG", "GET_ACCOUNTS", "READ_PHONE_STATE"],
      },
      {
        title: "Vị trí / Mic / Camera",
        keys: ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "RECORD_AUDIO", "CAMERA"],
      },
      {
        title: "Hệ thống",
        keys: [
          "SYSTEM_ALERT_WINDOW",
          "REQUEST_INSTALL_PACKAGES",
          "INSTALL_PACKAGES",
          "DELETE_PACKAGES",
          "REBOOT",
        ],
      },
    ];
    const allPerms = new Set([
      ...(d.permissions?.requested || []),
      ...(d.permissions?.declared || []),
    ]);
    let html = "";
    groups.forEach((g) => {
      const hits = g.keys.filter((k) => allPerms.has(k));
      if (hits.length) {
        html += `<div class="section"><div class="section__title">${g.title}</div><ul class="list">${hits
          .map((x) => `<li>${x}</li>`)
          .join("")}</ul></div>`;
      }
    });
    const rest = [...allPerms].filter(
      (p) => !groups.some((g) => g.keys.includes(p))
    );
    if (rest.length) {
      html += `<div class="section"><div class="section__title">Khác</div><ul class="list">${rest
        .slice(0, 200)
        .map((x) => `<li>${x}</li>`)
        .join("")}</ul></div>`;
    }
    tabContent.innerHTML = html || "<p class='muted'>No permissions.</p>";
  } else if (tab === "components") {
    const lines = [];
    ["activities", "services", "receivers", "providers"].forEach((k) => {
      lines.push(k.toUpperCase() + ":");
      (d.components?.[k] || []).forEach((c) => {
        lines.push(`- ${c.name}  exported=${c.exported}  perm=${c.permission}`);
      });
      lines.push("");
    });
    tabContent.textContent = lines.join("\n");
  } else if (tab === "api_calls") {
    const suspicious = [
      "Runtime.exec",
      "ProcessBuilder",
      "DexClassLoader",
      "PathClassLoader",
      "defineClass",
      "System.loadLibrary",
      "Runtime.load",
      "Class.forName",
      "getDeclaredField",
      "getMethod",
      "getDeviceId",
      "getSubscriberId",
      "getLine1Number",
    ];
    const hits = (d.api_calls || []).filter((c) => {
      const s = c.signature || `${c.class}.${c.name}`;
      return suspicious.some((x) => String(s).includes(x));
    });
    const html = [
      `<div class="section"><div class="section__title">API đáng ngờ</div>`,
      hits.length
        ? `<ul class="list">${hits
            .slice(0, 200)
            .map((c) => `<li>${c.signature || `${c.class}.${c.name}`}</li>`)
            .join("")}</ul>`
        : `<div class="muted-small">Không phát hiện API đáng ngờ.</div>`,
      `</div>`,
      `<div class="section"><div class="section__title">Tất cả API (rút gọn)</div><div class="muted-small">Hiển thị 200 dòng đầu.</div></div>`,
      `<pre class="muted-small">${(d.api_calls || [])
        .slice(0, 200)
        .map((c) => c.signature || `${c.class}.${c.name}`)
        .join("\n")}</pre>`,
    ].join("");
    tabContent.innerHTML = html;
  } else if (tab === "network") {
    const lines = [
      "URLs:",
      ...(d.network?.urls || []).map((x) => `- ${x}`),
      "",
      "Domains:",
      ...(d.network?.domains || []).map((x) => `- ${x}`),
      "",
      "IPs:",
      ...(d.network?.ips || []).map((x) => `- ${x}`),
    ];
    tabContent.textContent = lines.join("\n");
  } else if (tab === "strings") {
    tabContent.textContent = (d.strings || []).slice(0, 500).join("\n");
  } else if (tab === "certs") {
    tabContent.textContent = (d.certificates || [])
      .map((c) => c.sha256 || c.repr)
      .join("\n");
  }
}
