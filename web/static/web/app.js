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
let _radarChart = null;   // Chart.js instances — kept to destroy before re-create
let _pieChart   = null;
let _histChart  = null;
let _avgChart   = null;

// Stats overlay
document.getElementById("openStats")?.addEventListener("click", loadStats);
document.getElementById("closeStats")?.addEventListener("click", () => {
  document.getElementById("statsOverlay").style.display = "none";
});

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
    console.log("[ML] ml_prediction:", data.ml_prediction);
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
  renderAHP(data);
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

  // ── Heuristic reasons / notes (always computed for rule display) ──────────
  let heuristicScore = 0;
  const notes = [];
  const reasons = [];

  const hitPerms = [...dangerPerms].filter((p) => perms.has(p));
  if (hitPerms.length) {
    heuristicScore += Math.min(40, hitPerms.length * 4);
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
    heuristicScore += Math.min(35, hitApis.length * 5);
    const sample = hitApis.slice(0, 5).join(", ");
    notes.push(`API đáng ngờ: ${sample}`);
    reasons.push(`Dùng API nguy cơ cao (vd: ${sample})`);
  }

  if (exported.length) {
    heuristicScore += Math.min(15, exported.length);
    reasons.push(`Có ${exported.length} component exported`);
  }

  const netCount =
    (d.network?.urls?.length || 0) +
    (d.network?.domains?.length || 0) +
    (d.network?.ips?.length || 0);
  if (netCount > 0) {
    heuristicScore += Math.min(10, Math.ceil(netCount / 10));
    reasons.push(`Phát hiện ${netCount} chỉ dấu mạng (URL/domain/IP)`);
  }
  heuristicScore = Math.min(100, heuristicScore);

  // ── Decide which score to display ────────────────────────────────────────
  const ml = d.ml_prediction;
  const useML = ml && !ml.error && typeof ml.score === "number";

  let score = useML ? ml.score : heuristicScore;
  score = Math.min(100, Math.max(0, Math.round(score)));

  riskScoreEl.textContent = score;

  // Show ML badge / source note
  if (riskNotesEl) {
    if (useML) {
      const conf = (ml.probability * 100).toFixed(1);
      const modelNote = `[AI Model] Xác suất malware: ${conf}% (Drebin-215 Random Forest)`;
      riskNotesEl.textContent =
        notes.length > 0
          ? modelNote + " | " + notes.join(" | ")
          : modelNote;
    } else {
      riskNotesEl.textContent =
        notes.length > 0
          ? "[Heuristic] " + notes.join(" | ")
          : "Không thấy dấu hiệu nhạy cảm nổi bật.";
    }
  }

  riskVerdictEl.classList.remove("safe", "warn", "bad");
  riskAdviceEl.classList.remove("safe", "warn", "bad");
  if (score < 25) {
    riskVerdictEl.textContent = useML ? "AI: Lành tính" : "Nguy cơ thấp";
    riskVerdictEl.classList.add("safe");
    riskAdviceEl.textContent =
      "Khuyến nghị: Có thể cài đặt, nhưng vẫn nên tải từ nguồn tin cậy.";
    riskAdviceEl.classList.add("safe");
  } else if (score < 55) {
    riskVerdictEl.textContent = useML ? "AI: Đáng ngờ" : "Nguy cơ trung bình";
    riskVerdictEl.classList.add("warn");
    riskAdviceEl.textContent =
      "Khuyến nghị: Cân nhắc trước khi cài đặt, kiểm tra quyền và nguồn tải.";
    riskAdviceEl.classList.add("warn");
  } else {
    riskVerdictEl.textContent = useML ? "AI: Malware" : "Nguy cơ cao";
    riskVerdictEl.classList.add("bad");
    riskAdviceEl.textContent =
      "Khuyến nghị: Không nên cài đặt nếu không thực sự cần và không rõ nguồn gốc.";
    riskAdviceEl.classList.add("bad");
  }

  riskReasonsEl.innerHTML = "";
  if (useML) {
    // Add ML result as first item
    const liML = document.createElement("li");
    liML.textContent = `[AI] ${ml.is_malware ? "Phát hiện MALWARE" : "Lành tính (Benign)"} — xác suất ${(ml.probability * 100).toFixed(1)}%`;
    liML.style.fontWeight = "bold";
    riskReasonsEl.appendChild(liML);
  }
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

// ---------------------------------------------------------------------------
// AHP panel renderer
// ---------------------------------------------------------------------------
const _AHP_COLORS = {
  C1: "#e74c3c", C2: "#e67e22", C3: "#f1c40f", C4: "#9b59b6",
};
const _AHP_LABELS = {
  C1: "C1 – Permissions",
  C2: "C2 – API Calls",
  C3: "C3 – Intents",
  C4: "C4 – Commands/IPC",
};
const _AHP_RAW_LABELS = ["1", "2", "4", "3", "1/2", "1", "3", "2",
                          "1/4", "1/3", "1", "1/2", "1/3", "1/2", "2", "1"];

function _ahpMatrix(data, id, extraCols, headerExtra, footerHTML) {
  const el = document.getElementById(id);
  if (!el) return;
  const criteria = data.criteria || ["C1","C2","C3","C4"];
  const labels   = data.criteria_labels || {};
  const shortL   = criteria.map(k => `${k}<br><small>${labels[k] || ""}</small>`);

  let head = `<thead><tr><th></th>${shortL.map(l => `<th>${l}</th>`).join("")}${headerExtra || ""}</tr>`;
  // col-sums row if provided
  if (data.col_sums) {
    head += `<tr class="ahp__colsum"><td>Tổng cột</td>${data.col_sums.map(v => `<td>${v.toFixed(3)}</td>`).join("")}${(extraCols||[]).map(() => "<td>—</td>").join("")}</tr>`;
  }
  head += `</thead>`;

  const rows = data.matrix.map((row, r) => {
    const cells = row.map((v, c) =>
      `<td${r === c ? ' class="ahp__diag"' : ""}>${typeof v === "number" ? v.toFixed(3) : v}</td>`
    ).join("");
    const extra = (extraCols || []).map(fn => `<td class="ahp__weight-cell">${fn(r)}</td>`).join("");
    return `<tr><td class="ahp__row-label">${criteria[r]}<br><small style="font-weight:400">${labels[criteria[r]] || ""}</small></td>${cells}${extra}</tr>`;
  }).join("");

  el.innerHTML = `<table class="ahp__matrix"><colgroup></colgroup>${head}<tbody>${rows}</tbody>${footerHTML ? `<tfoot><tr><td colspan="${criteria.length + 1 + (extraCols||[]).length}" class="ahp__cr">${footerHTML}</td></tr></tfoot>` : ""}</table>`;
}

function renderAHP(data) {
  const panel = document.getElementById("ahpPanel");
  const ml = data.ml_prediction;
  if (!panel) return;
  if (!ml || ml.error || !ml.ahp) {
    panel.style.display = "none";
    return;
  }
  panel.style.display = "";

  // Clear previously injected dynamic sections (for re-analysis)
  panel.querySelectorAll(".ahp__lambda-section, .ahp__sum-row").forEach(el => el.remove());

  const ahp = ml.ahp;
  const criteria = ahp.criteria || ["C1","C2","C3","C4"];

  // ── ① Combined score + verdict ───────────────────────────────────────────
  const combinedEl = document.getElementById("ahpCombined");
  if (combinedEl) combinedEl.textContent = Math.round(ahp.combined * 100) + " / 100";

  const verdictEl = document.getElementById("ahpVerdict");
  if (verdictEl) {
    verdictEl.textContent = ahp.verdict || "—";
    verdictEl.className = "ahp__verdict " + (ahp.verdict_class || "");
  }

  const badgeEl = document.getElementById("ahpModelBadge");
  if (badgeEl) {
    const m = ml.model_metrics;
    if (m) {
      const acc = (m.accuracy * 100).toFixed(1);
      badgeEl.textContent = `Model: ${acc}% acc · ROC-AUC ${m.roc_auc.toFixed(3)}`;
    } else {
      badgeEl.textContent = "99.0% acc · ROC-AUC 0.999";
    }
  }

  // ── ② Consistency grid ───────────────────────────────────────────────────
  const consEl = document.getElementById("ahpConsistency");
  if (consEl) {
    const cr   = ahp.CR ?? 0;
    const ci   = ahp.CI ?? 0;
    const ri   = ahp.RI ?? 0.9;
    const lmax = ahp.lam_max ?? 0;
    const ok   = ahp.consistent;
    const crCls = ok ? "ahp__kpi--ok" : "ahp__kpi--fail";
    const crIcon = ok ? "✓ Nhất quán" : "✗ Không nhất quán";

    const kpis = [
      { label: "n (số tiêu chí)", value: criteria.length },
      { label: "λ<sub>max</sub>", value: lmax.toFixed(4) },
      { label: "CI = (λ<sub>max</sub>−n)/(n−1)", value: ci.toFixed(4) },
      { label: "RI (Saaty, n=4)", value: ri.toFixed(2) },
      { label: "CR = CI / RI", value: cr.toFixed(4), cls: crCls },
      { label: "Ngưỡng CR < 0.10", value: crIcon, cls: crCls },
    ];

    consEl.innerHTML = kpis.map(k =>
      `<div class="ahp__kpi ${k.cls || ''}">
         <div class="ahp__kpi-value">${k.value}</div>
         <div class="ahp__kpi-label">${k.label}</div>
       </div>`
    ).join("");

    // per-criterion λ_i breakdown
    const lambdas = ahp.lambdas || {};
    const lambdaRows = criteria.map(k => {
      const li = lambdas[k] ?? "—";
      const diff = typeof li === "number" ? (li - (lmax ?? li)).toFixed(4) : "—";
      const color = _AHP_COLORS[k];
      return `<tr>
        <td><span style="display:inline-block;width:10px;height:10px;background:${color};border-radius:2px"></span> ${k}</td>
        <td>${ahp.criteria_labels?.[k] || ""}</td>
        <td>${(ahp.weights?.[k] * 100).toFixed(2)}%</td>
        <td>${ahp[`S_${k}`] !== undefined ? (ahp[`S_${k}`] * 100).toFixed(1) + "%" : "—"}</td>
        <td>${typeof li === "number" ? li.toFixed(4) : li}</td>
        <td>${diff}</td>
      </tr>`;
    }).join("");

    consEl.insertAdjacentHTML("afterend",
      `<div class="ahp__lambda-section">
         <div class="ahp__section-title" style="margin-top:10px">λ<sub>i</sub> per tiêu chí — véc-tơ trọng số cuối cùng</div>
         <table class="ahp__matrix ahp__lambda-tbl">
           <thead><tr><th>Tiêu chí</th><th>Mô tả</th><th>w<sub>i</sub></th><th>S<sub>i</sub> (APK này)</th><th>λ<sub>i</sub></th><th>λ<sub>i</sub> − λ<sub>max</sub></th></tr></thead>
           <tbody>${lambdaRows}</tbody>
           <tfoot><tr>
             <td colspan="4" class="ahp__cr">λ<sub>max</sub> = ${lmax.toFixed(4)} &nbsp;·&nbsp; CI = ${ci.toFixed(4)} &nbsp;·&nbsp; CR = ${cr.toFixed(4)} ${ok ? "✓ &lt; 0.10 — nhất quán" : "✗ ≥ 0.10 — không nhất quán"}</td>
             <td colspan="2"></td>
           </tr></tfoot>
         </table>
       </div>`
    );
  }

  // ── ③ Step 1 – raw pairwise matrix A ────────────────────────────────────
  const rawA = ahp.A_matrix;
  if (rawA) {
    _ahpMatrix(
      { ...ahp, matrix: rawA, col_sums: ahp.col_sums },
      "ahpMatrixA",
      [r => `<b>${(ahp.weights_list?.[r] * 100 || 0).toFixed(2)}%</b>`],
      `<th class="ahp__w-col">w<sub>i</sub></th>`,
      `Tổng cột = ${(ahp.col_sums || []).map(v => v.toFixed(3)).join(", ")}`
    );
  }

  // ── ④ Step 2 – normalised matrix ────────────────────────────────────────
  const normM = ahp.norm_matrix;
  if (normM) {
    _ahpMatrix(
      { ...ahp, matrix: normM, col_sums: null },
      "ahpMatrixNorm",
      [r => `<b>${(ahp.weights_list?.[r] * 100 || 0).toFixed(2)}%</b>`],
      `<th class="ahp__w-col">w<sub>i</sub> (trung bình hàng)</th>`,
      null
    );

    // Weight bar chart
    const wBarEl = document.getElementById("ahpWeightsBar");
    if (wBarEl) {
      wBarEl.innerHTML = criteria.map((k, i) => {
        const w = (ahp.weights_list?.[i] || 0) * 100;
        return `<div class="ahp__bar-row">
          <div class="ahp__bar-label">${k}<span class="ahp__bar-weight">${w.toFixed(1)}%</span></div>
          <div class="ahp__bar-track"><div class="ahp__bar-fill" style="width:${w}%;background:${_AHP_COLORS[k]}"></div></div>
          <div class="ahp__bar-count">${w.toFixed(2)}%</div>
        </div>`;
      }).join("");
    }
  }

  // ── ⑤ Step 3 – λ_i table (detailed) ────────────────────────────────────
  const lambdaTableEl = document.getElementById("ahpLambdaTable");
  if (lambdaTableEl) {
    const v = ahp.v || criteria.map(k => (ahp.lambdas?.[k] ?? 0) * (ahp.weights_list?.[criteria.indexOf(k)] ?? 0));
    const lmbds = ahp.lambdas || {};
    const rows = criteria.map((k, i) => {
      const wi   = ahp.weights_list?.[i] ?? 0;
      const vi   = v[i] ?? 0;
      const li   = lmbds[k] ?? 0;
      return `<tr>
        <td>${k}</td>
        <td>${ahp.criteria_labels?.[k] || ""}</td>
        <td>${wi.toFixed(4)}</td>
        <td>${vi.toFixed(4)}</td>
        <td><b>${li.toFixed(4)}</b></td>
      </tr>`;
    }).join("");
    lambdaTableEl.innerHTML = `
      <table class="ahp__matrix">
        <thead><tr><th>Tiêu chí</th><th>Mô tả</th><th>w<sub>i</sub></th><th>v<sub>i</sub> = (A×w)<sub>i</sub></th><th>λ<sub>i</sub> = v<sub>i</sub>/w<sub>i</sub></th></tr></thead>
        <tbody>${rows}</tbody>
        <tfoot><tr><td colspan="4" class="ahp__cr">λ<sub>max</sub> = mean(λ<sub>i</sub>) = ${(ahp.lam_max ?? 0).toFixed(4)}</td><td></td></tr></tfoot>
      </table>`;
  }

  // ── ⑥ Per-APK criteria bars with contribution ───────────────────────────
  const barsEl = document.getElementById("ahpBars");
  if (barsEl) {
    barsEl.innerHTML = criteria.map(k => {
      const n      = ahp[`n_${k}`] ?? 0;
      const N      = ahp[`N_${k}`] ?? 1;
      const S      = ahp[`S_${k}`] ?? 0;
      const w      = ahp.weights?.[k] ?? 0;
      const contrib = ahp.contrib?.[k] ?? (w * S);
      const barPct  = Math.round(S * 100);
      const contribPct = (contrib * 100).toFixed(2);
      const color   = _AHP_COLORS[k];
      return `
        <div class="ahp__bar-row ahp__bar-row--contrib">
          <div class="ahp__bar-label">${_AHP_LABELS[k] || k}
            <span class="ahp__bar-weight">w=${(w*100).toFixed(1)}%</span>
          </div>
          <div style="flex:1">
            <div class="ahp__bar-track">
              <div class="ahp__bar-fill" style="width:${barPct}%;background:${color}"></div>
            </div>
            <div class="ahp__contrib-row">
              <span class="ahp__contrib-note">Đóng góp = ${(w*100).toFixed(1)}% × ${barPct}% = <b>${contribPct}%</b></span>
            </div>
          </div>
          <div class="ahp__bar-count">${n}/${N} (${barPct}%)</div>
        </div>`;
    }).join("");

    barsEl.insertAdjacentHTML("afterend",
      `<div class="ahp__sum-row">
         AHP tổng = ${criteria.map(k => {
           const s = (ahp[`S_${k}`]??0), w = ahp.weights?.[k]??0;
           return `${(w*100).toFixed(1)}%×${Math.round(s*100)}%`;
         }).join(" + ")} = <b>${Math.round((ahp.ahp_score??0)*100)}%</b>
         &nbsp;·&nbsp; P<sub>AI</sub> = ${Math.round((ahp.ml_prob??0)*100)}%
         &nbsp;·&nbsp; Score = 0.4×${Math.round((ahp.ml_prob??0)*100)}% + 0.6×${Math.round((ahp.ahp_score??0)*100)}% = <b>${Math.round(ahp.combined*100)} / 100</b>
       </div>`
    );
  }

  // ── ⑦ Radar chart ───────────────────────────────────────────────────────
  const radarCanvas = document.getElementById("ahpRadar");
  if (radarCanvas && window.Chart) {
    if (_radarChart) { _radarChart.destroy(); _radarChart = null; }
    _radarChart = new Chart(radarCanvas, {
      type: "radar",
      data: {
        labels: criteria.map(k => `${k}\n${ahp.criteria_labels?.[k] || ""}`),
        datasets: [
          {
            label: "Tỉ lệ phát hiện (%)",
            data: criteria.map(k => Math.round((ahp[`S_${k}`] ?? 0) * 100)),
            backgroundColor: "rgba(231,76,60,0.15)",
            borderColor: "#e74c3c",
            borderWidth: 2,
            pointBackgroundColor: "#e74c3c",
            pointRadius: 4,
          },
          {
            label: "Trọng số AHP (%)",
            data: criteria.map(k => Math.round((ahp.weights?.[k] ?? 0) * 100)),
            backgroundColor: "rgba(74,127,208,0.1)",
            borderColor: "#4a7fd0",
            borderWidth: 2,
            borderDash: [5, 3],
            pointBackgroundColor: "#4a7fd0",
            pointRadius: 4,
          },
        ],
      },
      options: {
        responsive: false,
        scales: {
          r: {
            min: 0, max: 100,
            ticks: { stepSize: 20, font: { size: 10 } },
            pointLabels: { font: { size: 11 } },
          },
        },
        plugins: {
          legend: { display: true, position: "bottom", labels: { font: { size: 10 } } },
        },
      },
    });
  }

  // ── ⑧ Detail footer ─────────────────────────────────────────────────────
  const mlDetail = document.getElementById("ahpMlDetail");
  if (mlDetail) {
    mlDetail.textContent = `P_AI = ${Math.round((ahp.ml_prob ?? 0) * 100)}%  (w_ML = ${(ahp.w_ml ?? 0.4) * 100}%)`;
  }
  const ahpDetailEl = document.getElementById("ahpAhpDetail");
  if (ahpDetailEl) {
    ahpDetailEl.textContent = `AHP = ${Math.round((ahp.ahp_score ?? 0) * 100)}%  (w_AHP = ${(1 - (ahp.w_ml ?? 0.4)) * 100}%)`;
  }
}

// ---------------------------------------------------------------------------
// Stats overlay
// ---------------------------------------------------------------------------
async function loadStats() {
  const overlay = document.getElementById("statsOverlay");
  if (!overlay) return;
  overlay.style.display = "flex";

  const cardsEl = document.getElementById("statsCards");
  if (cardsEl) cardsEl.innerHTML = "<p class='muted' style='padding:12px'>Đang tải...</p>";

  try {
    const res = await fetch("/api/stats/");
    const d = await res.json();
    renderStats(d);
  } catch (e) {
    if (cardsEl) cardsEl.innerHTML = `<p class='muted' style='padding:12px'>Lỗi: ${e.message}</p>`;
  }
}

function renderStats(d) {
  // summary cards
  const cardsEl = document.getElementById("statsCards");
  if (cardsEl) {
    const avgScore = d.averages?.avg_combined != null
      ? Math.round(d.averages.avg_combined * 100) + " / 100"
      : "—";
    const malwarePct = d.total > 0 ? ((d.malware / d.total) * 100).toFixed(1) : "0";
    cardsEl.innerHTML = `
      <div class="stats-card">
        <div class="stats-card__value">${d.total}</div>
        <div class="stats-card__label">Tổng APK đã phân tích</div>
      </div>
      <div class="stats-card stats-card--bad">
        <div class="stats-card__value">${d.malware}</div>
        <div class="stats-card__label">Malware · ${malwarePct}%</div>
      </div>
      <div class="stats-card stats-card--safe">
        <div class="stats-card__value">${d.benign}</div>
        <div class="stats-card__label">Lành tính</div>
      </div>
      <div class="stats-card stats-card--warn">
        <div class="stats-card__value">${avgScore}</div>
        <div class="stats-card__label">Điểm rủi ro trung bình</div>
      </div>`;
  }

  // Pie chart – malware vs benign vs unknown
  const pieCanvas = document.getElementById("chartPie");
  if (pieCanvas && window.Chart) {
    if (_pieChart) { _pieChart.destroy(); _pieChart = null; }
    _pieChart = new Chart(pieCanvas, {
      type: "doughnut",
      data: {
        labels: ["Malware", "Lành tính", "Không xác định"],
        datasets: [{
          data: [d.malware, d.benign, d.unknown],
          backgroundColor: ["#e74c3c", "#1a8c5f", "#aaa"],
          borderWidth: 2,
          borderColor: "#eef1f7",
        }],
      },
      options: {
        responsive: false,
        plugins: { legend: { position: "bottom", labels: { font: { size: 11 } } } },
      },
    });
  }

  // Histogram – risk score buckets 0-9 = 0-10,10-20,...,90-100
  const histCanvas = document.getElementById("chartHist");
  if (histCanvas && window.Chart) {
    if (_histChart) { _histChart.destroy(); _histChart = null; }
    const labels = d.histogram.map((_, i) => `${i * 10}–${i * 10 + 10}`);
    const colors = d.histogram.map((_, i) => {
      if (i < 3) return "#1a8c5f";
      if (i < 7) return "#b37220";
      return "#e74c3c";
    });
    _histChart = new Chart(histCanvas, {
      type: "bar",
      data: {
        labels,
        datasets: [{ label: "Số APK", data: d.histogram, backgroundColor: colors }],
      },
      options: {
        responsive: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
      },
    });
  }

  // Avg criteria radar
  const avgCanvas = document.getElementById("chartAvg");
  if (avgCanvas && window.Chart) {
    if (_avgChart) { _avgChart.destroy(); _avgChart = null; }
    const av = d.averages;
    const avgScores = [
      Math.round((av?.avg_s_c1 ?? 0) * 100),
      Math.round((av?.avg_s_c2 ?? 0) * 100),
      Math.round((av?.avg_s_c3 ?? 0) * 100),
      Math.round((av?.avg_s_c4 ?? 0) * 100),
    ];
    _avgChart = new Chart(avgCanvas, {
      type: "radar",
      data: {
        labels: ["C1 Perms", "C2 APIs", "C3 Intents", "C4 Cmds"],
        datasets: [{
          label: "Trung bình (%)",
          data: avgScores,
          backgroundColor: "rgba(74,127,208,0.15)",
          borderColor: "#4a7fd0",
          borderWidth: 2,
          pointBackgroundColor: "#4a7fd0",
          pointRadius: 4,
        }],
      },
      options: {
        responsive: false,
        scales: { r: { min: 0, max: 100, ticks: { stepSize: 20, font: { size: 10 } } } },
        plugins: { legend: { display: false } },
      },
    });
  }

  // Recent scans table
  const tbody = document.getElementById("statsTableBody");
  if (tbody) {
    tbody.innerHTML = (d.recent || []).map((row, i) => {
      const score = row.ahp_combined != null ? Math.round(row.ahp_combined * 100) : "—";
      const prob  = row.ml_probability != null ? (row.ml_probability * 100).toFixed(1) + "%" : "—";
      const cls   = row.ahp_verdict === "NGUY HIỂM" ? "bad"
                  : row.ahp_verdict === "NGHI NGỜ" ? "warn" : "safe";
      return `<tr>
        <td>${i + 1}</td>
        <td class="stats-td-file">${row.filename || "—"}</td>
        <td class="stats-td-pkg">${row.package_name || "—"}</td>
        <td>${row.analyzed_at || "—"}</td>
        <td>${prob}</td>
        <td>${score}</td>
        <td><span class="verdict-badge ${cls}">${row.ahp_verdict || "—"}</span></td>
      </tr>`;
    }).join("") || "<tr><td colspan='7' class='muted'>Chưa có dữ liệu.</td></tr>";
  }
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
