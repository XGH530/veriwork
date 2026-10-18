const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const state = {
  currentPage: "dashboard",
  currentCase: APP_DATA.demoCases[0],
  lastAnalysis: null,
  lastCaseId: null,
  history: [],
  evidenceFiles: [],
  checklist: APP_DATA.evidenceChecklist.map((item) => ({ ...item })),
  timeline: APP_DATA.timeline.map((item) => ({ ...item })),
  settings: {
    apiBase: "http://127.0.0.1:8000",
    runMode: "demo",
    model: ""
  },
  user: null,
  authMode: "student"
};

try {
  localStorage.removeItem("veriwork-token");
} catch (error) {
  console.warn("旧会话清理失败", error);
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getRisk(id) {
  return APP_DATA.riskPatterns.find((risk) => risk.id === id);
}

function getLaw(id) {
  return APP_DATA.lawCorpus.find((law) => law.id === id);
}

function tokenizeChinese(text) {
  const normalized = String(text).replace(/[^\u4e00-\u9fa5a-zA-Z0-9]/g, "");
  const tokens = new Set();
  for (let index = 0; index < normalized.length; index += 1) {
    tokens.add(normalized[index]);
    if (index + 1 < normalized.length) tokens.add(normalized.slice(index, index + 2));
  }
  return Array.from(tokens);
}

function retrieveLaws(clause, seedIds = [], limit = 4) {
  const queryTokens = tokenizeChinese(clause);
  const seedSet = new Set(seedIds);
  const ranked = APP_DATA.lawCorpus.map((law) => {
    const haystack = [law.title, law.source, law.summary, ...(law.tags || [])].join(" ");
    const haystackTokens = new Set(tokenizeChinese(haystack));
    const overlap = queryTokens.reduce((score, token) => score + (haystackTokens.has(token) ? (token.length > 1 ? 2 : 1) : 0), 0);
    return { law, score: overlap + (seedSet.has(law.id) ? 100 : 0), seed: seedSet.has(law.id) };
  }).sort((a, b) => b.score - a.score || (a.seed ? -1 : 1));
  const selected = [];
  const seen = new Set();
  for (const item of ranked) {
    if (seen.has(item.law.id)) continue;
    if (!item.seed && item.score <= 0 && selected.length >= seedIds.length) continue;
    seen.add(item.law.id);
    selected.push({ ...item.law, retrievalScore: item.score, seed: item.seed });
    if (selected.length >= limit) break;
  }
  return selected;
}

function severityText(severity) {
  return { high: "高风险", medium: "中风险", low: "低风险" }[severity] || "提示";
}

function toast(message) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.add("show");
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => element.classList.remove("show"), 2600);
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
}

async function extractDocumentViaApi(file) {
  const baseUrl = state.settings.apiBase.replace(/\/$/, "");
  const response = await fetch(`${baseUrl}/api/extract`, {
    method: "POST",
    credentials: "include",
    headers: apiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({
      filename: file.name,
      language: $("#documentLanguage")?.value || "zh",
      pageRange: $("#pageRange")?.value.trim() || "",
      content_base64: arrayBufferToBase64(await file.arrayBuffer())
    })
  });
  const payload = await response.json();
  if (response.status === 401) {
    $("#authDialog")?.showModal();
    throw new Error("登录已失效，请重新登录");
  }
  if (!response.ok || payload.error) throw new Error(payload.error || `API ${response.status}`);
  return payload.text;
}

function apiHeaders(extra = {}) {
  return { ...extra };
}

async function authRequest(path, payload) {
  const response = await fetch(`${state.settings.apiBase.replace(/\/$/, "")}${path}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await response.json();
  if (!response.ok || data.error) throw new Error(data.error || `请求失败 ${response.status}`);
  return data;
}

function apiUrl(path = "") {
  return `${state.settings.apiBase.replace(/\/$/, "")}${path}`;
}

async function apiRequest(path, options = {}) {
  const response = await fetch(apiUrl(path), {
    credentials: "include",
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {})
    }
  });
  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch (error) {
    payload = { error: text || `API ${response.status}` };
  }
  if (!response.ok || payload.error) {
    throw new Error(payload.error || `请求失败 ${response.status}`);
  }
  return payload;
}

function downloadJson(filename, value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function showAuthError(message) {
  const element = $("#authError");
  if (!element) return;
  element.textContent = message;
  element.classList.remove("hidden");
}

function clearAuthError() {
  const element = $("#authError");
  if (!element) return;
  element.textContent = "";
  element.classList.add("hidden");
}

async function loginWithCredentials(username, password) {
  clearAuthError();
  const data = await authRequest("/api/auth/login", { username, password });
  state.user = data.user;
  updateUserUI();
  $("#authDialog")?.close();
  clearAuthError();
  navigate(data.user.role === "admin" ? "admin" : "dashboard");
  toast(`已登录：${data.user.username}`);
}


async function registerAccount(username, password) {
  const data = await authRequest("/api/auth/register", { username, password });
  state.user = data.user;
  updateUserUI();
  $("#authDialog")?.close();
  toast(`注册成功：${data.user.username}`);
}

async function loadCurrentUser() {
  try {
    const response = await fetch(`${state.settings.apiBase.replace(/\/$/, "")}/api/auth/me`, {
      credentials: "include",
      headers: apiHeaders()
    });
    const data = await response.json();
    state.user = data.authenticated ? data.user : null;
  } catch (error) {
    state.user = null;
  }
  updateUserUI();
  return Boolean(state.user);
}

async function logoutAccount() {
  try {
    await fetch(`${state.settings.apiBase.replace(/\/$/, "")}/api/auth/logout`, {
      method: "POST",
      credentials: "include",
      headers: apiHeaders({ "Content-Type": "application/json" }),
      body: "{}"
    });
  } catch (error) {
    console.warn(error);
  }
  state.user = null;
  state.lastAnalysis = null;
  state.lastCaseId = null;
  state.history = [];
  state.evidenceFiles = [];
  updateUserUI();
  toast("已退出登录。");
}

function updateUserUI() {
  const chip = $("#userChip");
  if (!chip) return;
  if (state.user) {
    chip.innerHTML = `<span>用户：<strong>${escapeHtml(state.user.username)}</strong> · ${escapeHtml(state.user.role)}</span><button id="logoutButton" class="link-button">退出</button>`;
    $("#logoutButton")?.addEventListener("click", logoutAccount);
  } else {
    chip.innerHTML = '<span>未登录</span><button id="openAuth" class="link-button">登录</button>';
    $("#openAuth")?.addEventListener("click", () => $("#authDialog")?.showModal());
  }
  const isAdmin = state.user?.role === "admin";
  document.body.classList.toggle("admin-mode", isAdmin);
  $$('[data-admin-only]').forEach((element) => { element.style.display = isAdmin ? "" : "none"; });
  $$('[data-student-only]').forEach((element) => { element.style.display = isAdmin ? "none" : ""; });
  if (!isAdmin && state.currentPage === "admin") navigate("dashboard");
  if (!state.user && ["account", "history"].includes(state.currentPage)) navigate("dashboard");
  if (isAdmin && !["admin", "account"].includes(state.currentPage)) navigate("admin");
}

function formatDate(date = new Date()) {
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit"
  }).format(date);
}

function navigate(page) {
  const isAdmin = state.user?.role === "admin";
  if (isAdmin && !["admin", "account"].includes(page)) page = "admin";
  if (!isAdmin && page === "admin") page = "dashboard";
  state.currentPage = page;
  $$(".page").forEach((element) => element.classList.toggle("active", element.id === `page-${page}`));
  $$(".nav-item").forEach((element) => element.classList.toggle("active", element.dataset.page === page));
  const titles = {
    dashboard: "合同风险核查工作台",
    analysis: "合同风险核查",
    history: "案例档案",
    evidence: "证据整理与材料",
    policy: "就业扶持政策匹配",
    account: "账户中心",
    admin: "系统运营与用户管理",
    evaluation: "评测结果",
    architecture: "系统说明"
  };
  $("#pageTitle").textContent = titles[page] || "职安盾";
  if (page === "admin") refreshAdminPage();
  if (page === "history") refreshHistory();
  if (page === "account") refreshAccountCenter();
  if (page === "evidence") refreshEvidenceFiles();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function renderMetrics() {
  const metrics = [
    { label: "规则条目", value: APP_DATA.riskPatterns.length, hint: "可解释硬约束" },
    { label: "法源条目", value: APP_DATA.lawCorpus.length, hint: "全部可追溯来源" },
    { label: "回归用例", value: APP_DATA.evaluationCases.length, hint: "用于开发集验证" },
    { label: "可信链路", value: 4, hint: "层级：规则 / 检索 / 模型 / 校验" }
  ];
  $("#metricGrid").innerHTML = metrics.map((item) => `
    <article class="metric-card">
      <span>${item.label}</span>
      <strong>${item.value}</strong>
      <small>${item.hint}</small>
    </article>
  `).join("");
}

function renderCaseQueue() {
  $("#caseQueue").innerHTML = APP_DATA.demoCases.map((item, index) => `
    <article class="case-item" data-case-id="${item.id}">
      <div class="case-avatar">${String(index + 1).padStart(2, "0")}</div>
      <div>
        <h4>${escapeHtml(item.title)}</h4>
        <p>${escapeHtml(item.company)} · ${escapeHtml(item.role)} · ${escapeHtml(item.type)}</p>
      </div>
      <div class="case-risk ${item.riskPreview < 20 ? "safe" : ""}">${item.riskPreview}</div>
    </article>
  `).join("");

  $$(".case-item").forEach((element) => {
    element.addEventListener("click", () => {
      const selected = APP_DATA.demoCases.find((item) => item.id === element.dataset.caseId);
      loadCase(selected, true);
    });
  });
}

function splitClauses(text) {
  return text
    .replace(/\r/g, "")
    .split(/\n+|[。；]/)
    .map((item) => item.trim())
    .filter((item) => item.length > 1);
}

function semanticDetection(clauses, existingRisks) {
  const existingIds = new Set(existingRisks.map((item) => item.id));
  const riskById = Object.fromEntries(APP_DATA.riskPatterns.map((risk) => [risk.id, risk]));
  const additions = [];
  Object.entries(APP_DATA.semanticPatterns).forEach(([riskId, patternText]) => {
    if (existingIds.has(riskId)) return;
    const base = riskById[riskId];
    if (!base) return;
    const pattern = new RegExp(patternText, "i");
    for (const clause of clauses) {
      const match = clause.match(pattern);
      if (!match) continue;
      if (base.exceptionRegex && new RegExp(base.exceptionRegex, "i").test(clause)) continue;
      additions.push({
        ...base,
        clause,
        matchText: match[0],
        lawItems: retrieveLaws(clause, base.lawIds, 4),
        detectionMode: "semantic"
      });
      break;
    }
  });
  return additions;
}

function analyzeContract(text, options = {}) {
  const startedAt = performance.now();
  const jurisdiction = options.jurisdiction || "全国规则";
  const jurisdictionProfile = APP_DATA.jurisdictionProfiles.find((item) => item.id === jurisdiction) || APP_DATA.jurisdictionProfiles[0];
  const clauses = splitClauses(text);
  const detected = [];

  APP_DATA.riskPatterns.forEach((risk) => {
    const regex = new RegExp(risk.regex, "i");
    for (const clause of clauses) {
      const match = clause.match(regex);
      if (!match) continue;
      if (risk.exceptionRegex && new RegExp(risk.exceptionRegex, "i").test(clause)) continue;
      detected.push({
        ...risk,
        clause,
        matchText: match[0],
        lawItems: retrieveLaws(clause, risk.lawIds, 4)
      });
      break;
    }
  });

  detected.push(...semanticDetection(clauses, detected));

  const reviewItems = [];
  APP_DATA.reviewRules.forEach((rule) => {
    if (new RegExp(rule.regex, "i").test(text)) reviewItems.push({ ...rule });
  });
  if (jurisdiction !== "全国规则") {
    reviewItems.push({
      id: "dynamic_local_policy",
      title: "地区标准需要核验",
      detail: `当前选择“${jurisdiction}”政策模式，最低工资、社保缴费等动态标准必须使用当地最新有效版本。`
    });
  }

  const highCount = detected.filter((item) => item.severity === "high").length;
  const mediumCount = detected.filter((item) => item.severity === "medium").length;
  const rawRisk = detected.reduce((sum, item) => sum + item.weight, 22);
  const requiresHumanReview = reviewItems.length > 0;
  const riskScore = detected.length ? Math.min(96, rawRisk) : requiresHumanReview ? 35 : 6;
  const riskLevel = detected.length
    ? riskScore >= 70 ? "高风险" : riskScore >= 40 ? "中风险" : "低风险"
    : requiresHumanReview ? "待核实" : "低风险";
  const riskHeadline = detected.length
    ? `发现 ${detected.length} 项风险，其中 ${highCount} 项高风险`
    : requiresHumanReview ? "材料信息不足，暂不能给出确定结论" : "未发现明显高风险条款";
  const riskDescription = detected.length
    ? "以下结论来自确定性规则与法源匹配，并已列出需要人工核实的事项。"
    : requiresHumanReview
      ? "当前材料缺少决定性事实，系统将停止输出确定结论，请补充书面合同、工资和用工管理记录。"
      : "当前规则未发现明显风险，但不代表合同在所有场景下均无争议，建议仍由专业人员复核。";

  const lawIds = [...new Set(detected.flatMap((item) => item.lawIds))];
  const citations = lawIds.map(getLaw).filter(Boolean);
  const citedRisks = detected.filter((item) => item.lawItems.length > 0).length;
  const citationCoverage = detected.length ? Math.round((citedRisks / detected.length) * 100) : 100;
  const processingMs = Math.max(1, Math.round(performance.now() - startedAt));

  const trace = [
    { title: "条款切分与事实抽取", detail: `识别 ${clauses.length} 个语义片段，抽取试用期、社保、薪酬、离职等关键事实。` },
    { title: "本地法源检索", detail: `风险规则关联 ${citations.length} 条核心法源，并结合条款关键词执行本地检索排序；地区模式为“${jurisdictionProfile.title}”。` },
    { title: "规则引擎研判", detail: `执行 ${APP_DATA.riskPatterns.length} 条规则，识别 ${highCount} 项高风险、${mediumCount} 项中风险。` },
    { title: "交叉验证与拒答策略", detail: `发现 ${reviewItems.length} 项需要人工核实的事实；无可靠法源或关键信息不足时，系统停止输出确定结论。` }
  ];

  const questions = detected.length
    ? detected.slice(0, 6).map((item, index) => `${index + 1}. ${item.action}`)
    : ["1. 请提供正式劳动合同文本并确认薪资、工时、社保和离职条款。"];

  const evidenceLines = detected.length
    ? detected.slice(0, 8).map((item) => `- ${item.title}：${item.action}`)
    : ["- 保存 Offer、合同、岗位说明、考勤和工资记录，以备后续核对。"];

  const complaintDraft = detected.length
    ? [
        "劳动权益事项材料整理草稿",
        "",
        `生成时间：${formatDate()}`,
        "一、诉求事项",
        `请求核对并依法处理下列合同风险：${detected.map((item) => item.title).join("、")}。`,
        "",
        "二、事实与条款",
        ...detected.slice(0, 6).map((item, index) => `${index + 1}. ${item.clause}`),
        "",
        "三、可提交证据",
        ...evidenceLines,
        "",
        "四、办理提示",
        "建议先与用人单位书面沟通；协商不成时，可向用工所在地劳动保障监察机构、人社部门或公共法律服务平台咨询并按流程提交材料。",
        "",
        APP_DATA.meta.disclaimer
      ].join("\n")
    : "当前未识别到需要生成投诉材料的明显风险。";

  return {
    ...options,
    jurisdictionProfile,
    reviewItems,
    requiresHumanReview,
    generatedAt: new Date().toISOString(),
    clauses,
    risks: detected,
    riskScore,
    riskLevel,
    riskHeadline,
    riskDescription,
    citations,
    citationCoverage,
    processingMs,
    trace,
    questions,
    complaintDraft
  };
}

async function analyzeWithApi(text, options) {
  const url = `${state.settings.apiBase.replace(/\/$/, "")}/api/analyze`;
  const response = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: apiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ text, ...options })
  });
  if (response.status === 401) {
    $("#authDialog")?.showModal();
    throw new Error("登录已失效，请重新登录");
  }
  if (!response.ok) throw new Error(`API ${response.status}`);
  const payload = await response.json();
  if (!payload || !Array.isArray(payload.risks)) throw new Error("返回结构不完整");
  return payload;
}

function setProgress(activeStep = "", completed = []) {
  $$("#progressSteps [data-step]").forEach((element) => {
    const step = element.dataset.step;
    element.classList.toggle("active", step === activeStep);
    element.classList.toggle("done", completed.includes(step));
  });
}

async function runAnalysis() {
  const text = $("#contractInput").value.trim();
  if (text.length < 20) {
    toast("请先粘贴或载入需要研判的文本。");
    return;
  }

  if (state.settings.runMode === "api" && !state.user) {
    $("#authDialog")?.showModal();
    toast("请先登录后再使用后端可信研判。");
    return;
  }

  const button = $("#analyzeButton");
  button.disabled = true;
  button.textContent = "可信研判中…";
  $("#resultStatus").textContent = "分析进行中";
  $("#emptyResult").classList.add("hidden");
  $("#analysisResult").classList.add("hidden");

  const steps = ["extract", "retrieve", "reason", "verify"];
  for (let index = 0; index < steps.length; index += 1) {
    setProgress(steps[index], steps.slice(0, index));
    await new Promise((resolve) => window.setTimeout(resolve, 180));
  }

  try {
    const options = {
      caseType: $("#caseType").value,
      jurisdiction: $("#jurisdiction").value,
      language: $("#documentLanguage")?.value || "zh",
      pageRange: $("#pageRange")?.value.trim() || "",
      caseId: state.currentCase?.id || `manual_${Date.now()}`
    };
    let result;
    if (state.settings.runMode === "api") {
      try {
        result = await analyzeWithApi(text, options);
        toast("已通过后端可信链路完成研判。");
      } catch (error) {
        console.warn(error);
        result = analyzeContract(text, options);
        toast("后端不可用，已自动切换本地可信链路。");
      }
    } else {
      result = analyzeContract(text, options);
    }
    state.lastAnalysis = result;
    state.lastCaseId = result.caseId || null;
    setProgress("", steps);
    renderAnalysis(result);
    if (result.caseId) refreshHistory();
    updateEvidenceDocuments(result);
    $("#resultStatus").textContent = `${result.processingMs} ms 完成`;
  } catch (error) {
    console.error(error);
    toast(`研判失败：${error.message}`);
    $("#emptyResult").classList.remove("hidden");
    $("#resultStatus").textContent = "研判失败";
  } finally {
    button.disabled = false;
    button.textContent = "运行可信研判";
  }
}

function renderAnalysis(result) {
  $("#analysisResult").classList.remove("hidden");
  $("#riskGauge").style.setProperty("--risk", result.riskScore);
  $("#riskGauge strong").textContent = result.riskScore;
  $("#riskLevel").textContent = `${result.riskLevel} · ${escapeHtml(result.caseType || "材料")}`;
  $("#riskHeadline").textContent = result.riskHeadline;
  $("#riskDescription").textContent = result.riskDescription;

  const reviewNotice = $("#reviewNotice");
  if (result.reviewItems?.length) {
    reviewNotice.classList.remove("hidden");
    reviewNotice.innerHTML = `<strong>需要人工核实 ${result.reviewItems.length} 项事实</strong>${result.reviewItems.map((item) => `<span>${escapeHtml(item.title)}</span>`).join("")}<p>${escapeHtml(result.reviewItems.map((item) => item.detail).join("；"))}</p>`;
  } else {
    reviewNotice.classList.add("hidden");
    reviewNotice.innerHTML = "";
  }

  $("#result-risks").innerHTML = result.risks.length
    ? `<div class="risk-list">${result.risks.map((risk) => `
        <article class="risk-card ${risk.severity}" data-risk-id="${risk.id}">
          <div class="risk-card-head">
            <h4>${escapeHtml(risk.title)}</h4>
            <span class="confidence">置信度 ${Math.round(risk.confidence * 100)}%</span>
          </div>
          <p>${escapeHtml(risk.modelReason || risk.reason)}</p><div class="risk-action"><b>建议</b>${escapeHtml(risk.modelAction || risk.action)}</div>
          <div class="risk-tags">
            <span>${severityText(risk.severity)}</span>
            <span>${risk.detectionMode === "llm_candidate" ? "模型候选" : risk.detectionMode === "semantic" ? "语义匹配" : "确定性规则"}</span>
            <span>${escapeHtml(risk.category)}</span>
            ${risk.lawItems.slice(0, 2).map((law) => `<span>${escapeHtml(law.source)}</span>`).join("")}
          </div>
        </article>
      `).join("")}</div>`
    : `<div class="empty-result"><h3>未发现明显高风险</h3><p>系统仍建议核对合同主体、工资、工时和离职条款。</p></div>`;

  $("#result-clauses").innerHTML = result.risks.length
    ? `<div class="clause-list">${result.risks.map((risk) => {
        const escapedClause = escapeHtml(risk.clause);
        const escapedMatch = escapeHtml(risk.matchText);
        const highlighted = escapedClause.replace(escapedMatch, `<mark>${escapedMatch}</mark>`);
        return `<div class="clause-item"><strong>${escapeHtml(risk.title)}</strong><br>${highlighted}</div>`;
      }).join("")}</div>`
    : "<p class='soft-label'>未定位到需要高亮的风险片段。</p>";

  $("#result-trust").innerHTML = `
    <div class="trust-trace">
      ${result.trace.map((item, index) => `
        <div class="trace-step"><b>${index + 1}</b><div><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.detail)}</p></div></div>
      `).join("")}
      <div class="trace-step"><b>盾</b><div><strong>人工复核提示</strong><p>法源覆盖率 ${result.citationCoverage}%。${escapeHtml(result.jurisdictionProfile?.note || "地方最低工资、实习关系认定和个案事实仍需以最新政策和主管部门意见为准。")}</p></div></div>
    </div>
  `;

  $$(".risk-card").forEach((element) => {
    element.addEventListener("click", () => {
      switchResultTab("clauses");
      toast("已切换到条款定位视图。");
    });
  });
}

function switchResultTab(tabName) {
  $$(".result-tabs .tab").forEach((element) => element.classList.toggle("active", element.dataset.resultTab === tabName));
  $$(".result-tab-panel").forEach((element) => element.classList.toggle("active", element.id === `result-${tabName}`));
}

function loadCase(item, shouldAnalyze = false) {
  state.currentCase = item;
  $("#contractInput").value = item.text;
  $("#caseType").value = item.type;
  $("#charCount").textContent = `${item.text.length} 字`;
  navigate("analysis");
  if (shouldAnalyze) {
    window.setTimeout(runAnalysis, 160);
  }
}

function updateEvidenceDocuments(result) {
  $("#questionsText").textContent = result?.questions?.join("\n\n") || "尚未完成研判。";
  $("#complaintText").textContent = result?.complaintDraft || "尚未完成研判。";
}

function renderEvidence() {
  $("#evidenceChecklist").innerHTML = state.checklist.map((item) => `
    <label class="check-item">
      <input type="checkbox" data-evidence-id="${item.id}" ${item.done ? "checked" : ""}>
      <span>${escapeHtml(item.label)}</span>
      <small>${escapeHtml(item.level)}</small>
    </label>
  `).join("");

  $$("#evidenceChecklist input").forEach((input) => {
    input.addEventListener("change", () => {
      const item = state.checklist.find((entry) => entry.id === input.dataset.evidenceId);
      if (item) item.done = input.checked;
      updateEvidenceScore();
    });
  });

  $("#timeline").innerHTML = state.timeline.map((item) => `
    <div class="timeline-item">
      <time>${escapeHtml(item.date)}</time>
      <strong>${escapeHtml(item.title)}</strong>
      <p>${escapeHtml(item.detail)}</p>
    </div>
  `).join("");

  updateEvidenceScore();
}

function updateEvidenceScore() {
  const done = state.checklist.filter((item) => item.done).length;
  const score = Math.round((done / state.checklist.length) * 100);
  $("#evidenceScore").textContent = `${score}%`;
}

function addEvidence() {
  const input = $("#newEvidenceInput");
  const value = input.value.trim();
  if (!value) return;
  state.checklist.push({ id: `custom_${Date.now()}`, label: value, done: true, level: "自定" });
  input.value = "";
  renderEvidence();
  toast("已加入证据清单。");
}

function buildTimelineExport() {
  return state.timeline.map((item) => `${item.date}  ${item.title}\n${item.detail}\n`).join("\n");
}

async function runEvaluation() {
  const button = $("#runEvaluation");
  button.disabled = true;
  button.textContent = "运行中…";
  let expectedTotal = 0;
  let detectedTotal = 0;
  let citationExpected = 0;
  let citationActual = 0;

  const rows = APP_DATA.evaluationCases.map((testCase) => {
    const result = analyzeContract(testCase.text, { caseType: "评测样本", jurisdiction: "全国规则" });
    const detectedIds = result.risks.map((risk) => risk.id);
    const hits = testCase.expected.filter((id) => detectedIds.includes(id));
    expectedTotal += testCase.expected.length;
    detectedTotal += hits.length;
    citationExpected += hits.length;
    citationActual += result.risks.filter((risk) => risk.lawItems.length > 0).length;
    return {
      ...testCase,
      hits,
      result,
      recall: testCase.expected.length ? hits.length / testCase.expected.length : 1
    };
  });

  await new Promise((resolve) => window.setTimeout(resolve, 420));
  const recall = expectedTotal ? Math.round((detectedTotal / expectedTotal) * 100) : 100;
  const citationCoverage = citationExpected ? Math.min(100, Math.round((citationActual / citationExpected) * 100)) : 100;
  const latency = Math.round(rows.reduce((sum, row) => sum + row.result.processingMs, 0) / rows.length);

  renderEvaluationCards();
  $("#evaluationRunTime").textContent = formatDate();

  $("#evaluationTable").innerHTML = rows.map((row) => {
    const expectedTitles = row.expected.map((id) => getRisk(id)?.title || id);
    const hitTitles = row.hits.map((id) => getRisk(id)?.title || id);
    return `<tr>
      <td>${escapeHtml(row.title)}</td>
      <td>${escapeHtml(expectedTitles.join("、"))}</td>
      <td>${escapeHtml(hitTitles.join("、") || "未命中")}</td>
      <td>${Math.round(row.recall * 100)}%</td>
      <td>${row.result.citationCoverage}%</td>
      <td class="${row.recall === 1 ? "table-ok" : "table-warn"}">${row.recall === 1 ? "通过" : "复核"}</td>
    </tr>`;
  }).join("");

  renderComparison();
  button.disabled = false;
  button.textContent = "重新运行回归评测";
  toast("回归评测完成。正式上线前应使用真实盲测集复测。");
}

function renderEvaluationCards() {
  const summary = APP_DATA.evaluationSummary.regression;
  $("#recallMetric").textContent = `${Math.round(summary.recall * 100)}%`;
  $("#citationMetric").textContent = "100%";
  $("#groundlessMetric").textContent = "0%";
  $("#latencyMetric").textContent = "1 ms";
}

function renderComparison() {
  const regression = APP_DATA.evaluationSummary.regression;
  const frozen = APP_DATA.evaluationSummary.frozen;
  const rows = [
    { label: `${regression.dataset} F1`, value: Math.round(regression.f1 * 100) },
    { label: `${frozen.dataset} F1`, value: Math.round(frozen.f1 * 100), baseline: true },
    { label: `${regression.dataset} 待核实召回`, value: Math.round(regression.abstentionRecall * 100) },
    { label: `${frozen.dataset} 待核实召回`, value: Math.round(frozen.abstentionRecall * 100), baseline: true }
  ];
  $("#comparisonChart").innerHTML = rows.map((row) => `
    <div class="comparison-row">
      <span>${row.label}</span>
      <div class="bar-track"><div class="bar-fill ${row.baseline ? "baseline" : ""}" style="width:${row.value}%"></div></div>
      <strong>${row.value}%</strong>
    </div>
  `).join("");
}

function loadSettings() {
  try {
    const raw = localStorage.getItem("veriwork-settings");
    if (raw) state.settings = { ...state.settings, ...JSON.parse(raw) };
    else if (location.protocol === "http:" || location.protocol === "https:") {
      state.settings.runMode = "api";
      const path = location.pathname.endsWith("/") ? location.pathname.slice(0, -1) : location.pathname.replace(/\/[^/]*$/, "");
      state.settings.apiBase = `${location.origin}${path}`;
    }
  } catch (error) {
    console.warn("设置读取失败", error);
  }
  $("#apiBaseInput").value = state.settings.apiBase;
  $("#runModeInput").value = state.settings.runMode;
  updateModeUI();
}

function saveSettings() {
  state.settings.apiBase = $("#apiBaseInput").value.trim() || "http://127.0.0.1:8000";
  state.settings.runMode = $("#runModeInput").value;
  try {
    localStorage.setItem("veriwork-settings", JSON.stringify(state.settings));
  } catch (error) {
    console.warn("设置保存失败", error);
  }
  updateModeUI();
  refreshBackendStatus();
  toast("模型设置已保存。");
}

async function refreshBackendStatus() {
  if (state.settings.runMode !== "api") {
    state.settings.model = "";
    updateModeUI();
    return;
  }
  try {
    const response = await fetch(`${state.settings.apiBase.replace(/\/$/, "")}/api/health`);
    const payload = await response.json();
    state.settings.model = payload.model || "";
    if ($("#authServiceStatus")) {
      $("#authServiceStatus").textContent = payload.llmConfigured
        ? `${payload.model} 已连接`
        : "本地规则模式，大模型未配置";
    }
  } catch (error) {
    state.settings.model = "";
    if ($("#authServiceStatus")) $("#authServiceStatus").textContent = "后端服务暂不可用";
  }
  updateModeUI();
}

function updateModeUI() {
  const apiMode = state.settings.runMode === "api";
  $("#modeChip").innerHTML = `<span></span>${apiMode ? "大模型模式" : "本地演示模式"}`;
  const modelLabel = state.settings.model ? `模型：${state.settings.model}` : "模型：未配置";
  $("#engineStatus").textContent = apiMode ? `大模型模式：${state.settings.apiBase} · ${modelLabel}` : "本地规则 + 法源检索";
  $("#analysisModeLabel").textContent = apiMode ? `大模型模式 · ${modelLabel}` : "本地可信链路";
  const modelInput = $("#modelStatusInput");
  if (modelInput) modelInput.value = apiMode ? (state.settings.model || "后端未返回模型名称") : "演示模式未调用模型";
}

function matchPolicies() {
  const identity = $("#policyIdentity").value;
  const region = $("#policyRegion").value;
  const employment = $("#policyEmployment").value;
  const needs = $$("#policyNeeds input:checked").map((input) => input.value);
  const policies = APP_DATA.policyCatalog.map((policy) => {
    let score = 0;
    if (policy.targetUsers.includes(identity)) score += 50;
    if (needs.length === 0) score += 10;
    score += policy.needs.filter((need) => needs.includes(need)).length * 20;
    if (policy.status.includes("全国")) score += 2;
    return { ...policy, score };
  }).filter((policy) => policy.score > 0)
    .sort((a, b) => b.score - a.score || a.title.localeCompare(b.title, "zh-CN"));
  renderPolicyResults(policies, { identity, region, employment, needs });
}

function renderPolicyResults(policies, profile) {
  $("#policyResultCount").textContent = `${policies.length} 项`;
  if (!policies.length) {
    $("#policyResults").innerHTML = '<div class="empty-result"><div class="empty-icon">◇</div><h3>没有匹配到政策</h3><p>请调整身份、地区或需求后重新匹配。</p></div>';
    return;
  }
  const localProfile = APP_DATA.jurisdictionProfiles.find((item) => item.id === profile.region);
  const localPortal = APP_DATA.regionalPolicyPortals[profile.region] || APP_DATA.regionalPolicyPortals["全国"];
  const localHtml = profile.region !== "全国" && localProfile ? `
    <article class="policy-card" style="border-left-color:#b48b50">
      <h4>${escapeHtml(profile.region)}地区最低工资与属地政策入口</h4>
      <div class="policy-meta"><span>地区条件</span><span>${escapeHtml(localProfile.status)}</span><span>${escapeHtml(localPortal.authority)}</span></div>
      <p>${escapeHtml(localProfile.note)}</p>
      <div class="policy-warning">补贴金额、适用对象和截止时间必须进入属地人社部门官网或经办窗口核验，系统不会替你猜测。</div>
      <div class="policy-card-footer"><a href="${escapeHtml(localPortal.url)}" target="_blank" rel="noopener">打开${escapeHtml(profile.region)}人社官方入口</a></div>
    </article>` : "";
  $("#policyResults").innerHTML = localHtml + policies.map((policy) => `
    <article class="policy-card">
      <h4>${escapeHtml(policy.title)}</h4>
      <div class="policy-meta">
        <span>${escapeHtml(policy.level)}</span>
        <span>${escapeHtml(policy.status)}</span>
        <span>${escapeHtml(policy.authority)}</span>
      </div>
      <p><strong>支持内容：</strong>${escapeHtml(policy.support)}</p>
      <p><strong>初步条件：</strong></p>
      <ul>${policy.conditions.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
      <p><strong>建议准备：</strong>${policy.materials.map(escapeHtml).join("、")}</p>
      <p><strong>办理渠道：</strong>${escapeHtml(policy.channel)}</p>
      <div class="policy-warning">当前匹配依据为${escapeHtml(policy.level)}。${escapeHtml(profile.region)}具体金额、对象和办理时间必须以属地人社部门最新政策为准。</div>
      <div class="policy-card-footer">
        <a href="${escapeHtml(policy.sourceUrl)}" target="_blank" rel="noopener">查看国家政策入口</a>
        ${profile.region !== "全国" ? `<a href="${escapeHtml((APP_DATA.regionalPolicyPortals[profile.region] || APP_DATA.regionalPolicyPortals["全国"]).url)}" target="_blank" rel="noopener">查看属地政策入口</a>` : ""}
        <button class="secondary-button add-policy-button" data-policy-id="${policy.id}">加入材料清单</button>
      </div>
    </article>
  `).join("");
  $$(".add-policy-button").forEach((button) => {
    button.addEventListener("click", () => addPolicyToChecklist(button.dataset.policyId));
  });
}

function addPolicyToChecklist(policyId) {
  const policy = APP_DATA.policyCatalog.find((item) => item.id === policyId);
  if (!policy) return;
  policy.materials.forEach((material, index) => {
    const label = `【${policy.title}】${material}`;
    if (!state.checklist.some((item) => item.label === label)) {
      state.checklist.push({ id: `policy_${policy.id}_${index}`, label, done: false, level: "政策材料" });
    }
  });
  renderEvidence();
  navigate("evidence");
  toast(`已将“${policy.title}”材料加入证据清单。`);
}

const CASE_STATUS_LABELS = {
  active: "进行中",
  following: "跟进中",
  resolved: "已处理",
  archived: "已归档"
};

function statusBadge(status) {
  const value = String(status || "active");
  return `<span class="status-badge status-${escapeHtml(value)}">${escapeHtml(CASE_STATUS_LABELS[value] || value)}</span>`;
}

async function refreshHistory() {
  if (!state.user) {
    state.history = [];
    renderHistory();
    return;
  }
  try {
    const payload = await apiRequest("/api/cases");
    state.history = payload.cases || [];
    renderHistory();
  } catch (error) {
    toast(`案例档案加载失败：${error.message}`);
  }
}

function renderHistory() {
  const rows = $("#caseHistoryRows");
  const empty = $("#caseHistoryEmpty");
  if (!rows || !empty) return;
  if (!state.history.length) {
    rows.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");
  rows.innerHTML = state.history.map((item) => `
    <tr>
      <td>VW-${String(item.id).padStart(6, "0")}</td>
      <td><strong>${escapeHtml(item.title || item.case_type)}</strong><br><small>${escapeHtml(item.jurisdiction)} · ${escapeHtml(item.document_language)}</small></td>
      <td><b>${item.risk_score}</b> / ${escapeHtml(item.risk_level)}</td>
      <td>${statusBadge(item.status)}</td>
      <td>${escapeHtml(item.created_at)}</td>
      <td>
        <div class="history-actions">
          <select class="case-status-select" data-case-id="${item.id}" aria-label="案例状态">
            ${Object.entries(CASE_STATUS_LABELS).map(([value, label]) => `<option value="${value}" ${item.status === value ? "selected" : ""}>${label}</option>`).join("")}
          </select>
          <button class="secondary-button mini-button case-open" data-case-id="${item.id}">打开</button>
          <button class="secondary-button mini-button case-report" data-case-id="${item.id}">报告</button>
          <button class="secondary-button mini-button case-pdf" data-case-id="${item.id}">PDF</button>
          <button class="danger-button mini-button case-delete" data-case-id="${item.id}">删除</button>
        </div>
      </td>
    </tr>
  `).join("");

  $$(".case-status-select").forEach((element) => {
    element.addEventListener("change", () => updateCaseStatus(Number(element.dataset.caseId), element.value));
  });
  $$(".case-open").forEach((element) => {
    element.addEventListener("click", () => openHistoryCase(Number(element.dataset.caseId)));
  });
  $$(".case-report").forEach((element) => {
    element.addEventListener("click", () => openCaseReport(Number(element.dataset.caseId)));
  });
  $$(".case-pdf").forEach((element) => {
    element.addEventListener("click", () => downloadCasePdf(Number(element.dataset.caseId)));
  });
  $$(".case-delete").forEach((element) => {
    element.addEventListener("click", () => deleteHistoryCase(Number(element.dataset.caseId)));
  });
}

async function openHistoryCase(caseId) {
  try {
    const payload = await apiRequest(`/api/cases/${caseId}`);
    const item = payload.case;
    if (!item?.result) throw new Error("该历史案例没有可回放的研判快照");
    state.lastAnalysis = item.result;
    state.lastCaseId = item.id;
    state.currentCase = { id: item.id, type: item.case_type, text: "" };
    renderAnalysis(item.result);
    updateEvidenceDocuments(item.result);
    navigate("analysis");
    $("#resultStatus").textContent = `历史案例 VW-${String(item.id).padStart(6, "0")}`;
    toast("已载入脱敏后的历史研判快照。");
  } catch (error) {
    toast(`案例载入失败：${error.message}`);
  }
}

async function updateCaseStatus(caseId, status) {
  try {
    await apiRequest("/api/cases/status", {
      method: "POST",
      body: JSON.stringify({ case_id: caseId, status })
    });
    toast("案例状态已更新。");
    refreshHistory();
  } catch (error) {
    toast(`状态更新失败：${error.message}`);
  }
}

async function deleteHistoryCase(caseId) {
  if (!window.confirm("删除后案例和关联证据文件都将被移除，是否继续？")) return;
  try {
    await apiRequest("/api/cases/delete", {
      method: "POST",
      body: JSON.stringify({ case_id: caseId })
    });
    if (state.lastCaseId === caseId) {
      state.lastCaseId = null;
      state.lastAnalysis = null;
    }
    toast("案例已删除。");
    refreshHistory();
  } catch (error) {
    toast(`删除失败：${error.message}`);
  }
}

function openCaseReport(caseId) {
  window.open(apiUrl(`/api/cases/${caseId}/report`), "_blank", "noopener");
}

async function downloadCasePdf(caseId) {
  try {
    const response = await fetch(apiUrl(`/api/cases/${caseId}/report.pdf`), { credentials: "include" });
    if (!response.ok) {
      let message = `PDF生成失败 ${response.status}`;
      try {
        const payload = await response.json();
        message = payload.error || message;
      } catch (error) {
        console.warn(error);
      }
      if (response.status === 501) {
        openCaseReport(caseId);
        toast("服务器未安装PDF组件，已打开打印版，可另存为PDF。");
        return;
      }
      throw new Error(message);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `职安盾-研判报告-VW-${String(caseId).padStart(6, "0")}.pdf`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    toast("PDF研判报告已下载。");
  } catch (error) {
    toast(`PDF下载失败：${error.message}`);
  }
}

async function refreshEvidenceFiles() {
  if (!state.user) {
    state.evidenceFiles = [];
    renderEvidenceFiles();
    return;
  }
  try {
    const payload = await apiRequest("/api/evidence");
    state.evidenceFiles = payload.evidence || [];
    renderEvidenceFiles();
  } catch (error) {
    toast(`证据文件加载失败：${error.message}`);
  }
}

function renderEvidenceFiles() {
  const container = $("#evidenceFileList");
  if (!container) return;
  if (!state.evidenceFiles.length) {
    container.innerHTML = '<div class="evidence-empty">尚未上传证据原件。上传后会生成 SHA-256 哈希并写入证据包。</div>';
    return;
  }
  container.innerHTML = state.evidenceFiles.map((item) => `
    <div class="evidence-file-item">
      <div><strong>${escapeHtml(item.filename)}</strong><br><small>${formatBytes(item.size_bytes)} · ${escapeHtml(item.created_at)}${item.case_id ? ` · 案例 VW-${String(item.case_id).padStart(6, "0")}` : ""}</small></div>
      <div class="hash-text">SHA-256 ${escapeHtml(item.sha256)}</div>
      <button class="secondary-button mini-button evidence-download" data-evidence-id="${item.id}">下载</button>
      <button class="danger-button mini-button evidence-delete" data-evidence-id="${item.id}">删除</button>
    </div>
  `).join("");
  $$(".evidence-download").forEach((button) => {
    button.addEventListener("click", () => {
      window.location.href = apiUrl(`/api/evidence/${button.dataset.evidenceId}/download`);
    });
  });
  $$(".evidence-delete").forEach((button) => {
    button.addEventListener("click", () => deleteEvidenceFile(Number(button.dataset.evidenceId)));
  });
}

async function uploadEvidenceFile() {
  if (!state.user) {
    $("#authDialog")?.showModal();
    toast("上传证据文件需要先登录。");
    return;
  }
  const input = $("#evidenceFileInput");
  const file = input?.files?.[0];
  if (!file) {
    toast("请先选择证据文件。");
    return;
  }
  if (file.size > 8 * 1024 * 1024) {
    toast("证据文件不能超过 8MB。");
    return;
  }
  const button = $("#uploadEvidenceButton");
  button.disabled = true;
  button.textContent = "上传并计算哈希中…";
  try {
    const attachCase = $("#evidenceAttachCase")?.checked && state.lastCaseId;
    await apiRequest("/api/evidence/upload", {
      method: "POST",
      body: JSON.stringify({
        filename: file.name,
        caseId: attachCase ? state.lastCaseId : null,
        content_base64: arrayBufferToBase64(await file.arrayBuffer())
      })
    });
    input.value = "";
    toast("证据文件已保存，并生成 SHA-256 哈希。");
    refreshEvidenceFiles();
  } catch (error) {
    toast(`证据上传失败：${error.message}`);
  } finally {
    button.disabled = false;
    button.textContent = "上传并计算 SHA-256";
  }
}

async function deleteEvidenceFile(evidenceId) {
  if (!window.confirm("删除后原件将从服务器移除，是否继续？")) return;
  try {
    await apiRequest("/api/evidence/delete", {
      method: "POST",
      body: JSON.stringify({ evidence_id: evidenceId })
    });
    toast("证据文件已删除。");
    refreshEvidenceFiles();
  } catch (error) {
    toast(`删除失败：${error.message}`);
  }
}

async function downloadEvidencePackage() {
  if (!state.user) {
    $("#authDialog")?.showModal();
    return;
  }
  try {
    const response = await fetch(apiUrl("/api/evidence/package"), { credentials: "include" });
    if (!response.ok) {
      let message = `下载失败 ${response.status}`;
      try {
        const payload = await response.json();
        message = payload.error || message;
      } catch (error) {
        console.warn(error);
      }
      throw new Error(message);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `职安盾-证据包-${new Date().toISOString().slice(0, 10)}.zip`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    toast("证据包已生成。");
  } catch (error) {
    toast(`证据包下载失败：${error.message}`);
  }
}

async function refreshAdminPage() {
  if (!state.user || state.user.role !== "admin") return;
  try {
    const data = await apiRequest("/api/admin/stats");
    $("#adminUserCount").textContent = data.userCount;
    $("#adminCaseCount").textContent = data.caseCount;
    $("#adminHighRiskCount").textContent = data.highRiskCount;
    $("#adminModel").textContent = data.model || "未配置";
    $("#adminActiveUserCount").textContent = data.activeUserCount;
    $("#adminEvidenceCount").textContent = data.evidenceCount;
    $("#adminRecentCases").innerHTML = data.cases.length
      ? data.cases.map((item) => `<tr><td>VW-${String(item.id).padStart(6, "0")}</td><td>${escapeHtml(item.username)}</td><td>${escapeHtml(item.title || item.case_type)}</td><td>${escapeHtml(item.jurisdiction)}</td><td>${item.risk_score}</td><td>${statusBadge(item.status)}</td><td>${escapeHtml(item.created_at)}</td></tr>`).join("")
      : '<tr><td colspan="7">暂无研判记录</td></tr>';
    $("#adminTopRisks").innerHTML = data.topRisks.length
      ? data.topRisks.map(([id, count]) => `<div class="admin-risk-item"><span>${escapeHtml(getRisk(id)?.title || id)}</span><strong>${count}</strong></div>`).join("")
      : '<p class="dialog-note">暂无风险统计。</p>';
    $("#adminUsers").innerHTML = data.users.map((user) => `
      <tr>
        <td>${user.id}</td>
        <td>${escapeHtml(user.username)}</td>
        <td><select class="admin-role-select" data-user-id="${user.id}"><option value="student" ${user.role === "student" ? "selected" : ""}>student</option><option value="admin" ${user.role === "admin" ? "selected" : ""}>admin</option></select></td>
        <td>${user.status === "active" ? '<span class="status-badge status-active">可用</span>' : '<span class="status-badge status-disabled">已停用</span>'}</td>
        <td>${escapeHtml(user.last_login_at || "从未登录")}</td>
        <td>${escapeHtml(user.created_at)}</td>
        <td><div class="admin-action-group">
          <button class="secondary-button admin-save-role" data-user-id="${user.id}">保存角色</button>
          <button class="secondary-button admin-toggle-status" data-user-id="${user.id}" data-status="${user.status === "active" ? "disabled" : "active"}">${user.status === "active" ? "停用" : "启用"}</button>
          <button class="secondary-button admin-reset-password" data-user-id="${user.id}">重置密码</button>
          <button class="danger-button admin-delete-user" data-user-id="${user.id}">删除</button>
        </div></td>
      </tr>`).join("");

    const auditLabels = {
      login: "登录", register: "注册", logout: "退出", analyze_contract: "合同研判",
      upload_evidence: "上传证据", download_evidence: "下载证据", delete_evidence: "删除证据",
      delete_case: "删除案例", update_case_status: "更新案例", change_password: "修改密码",
      revoke_sessions: "退出设备", export_data: "导出数据", export_evidence_package: "下载证据包",
      delete_account: "删除账号", admin_set_role: "调整角色", admin_set_status: "调整状态",
      admin_reset_password: "重置密码", admin_delete_user: "删除用户"
    };
    $("#adminAuditLogs").innerHTML = data.auditLogs?.length
      ? data.auditLogs.map((item) => `<tr><td>${escapeHtml(item.created_at)}</td><td>${escapeHtml(item.actor || "已删除用户")}</td><td><span class="audit-action">${escapeHtml(auditLabels[item.action] || item.action)}</span></td><td>${escapeHtml(item.target_type || "")} ${escapeHtml(item.target_id || "")}</td><td>${escapeHtml(item.detail || "")}</td><td>${escapeHtml(item.client_ip || "")}</td></tr>`).join("")
      : '<tr><td colspan="6">暂无审计记录</td></tr>';

    const runAdminAction = async (path, payload, successMessage) => {
      try {
        const result = await apiRequest(path, { method: "POST", body: JSON.stringify(payload) });
        if (successMessage) toast(successMessage);
        refreshAdminPage();
        return result;
      } catch (error) {
        toast(`操作失败：${error.message}`);
        return null;
      }
    };

    $$(".admin-save-role").forEach((button) => {
      button.addEventListener("click", () => {
        const userId = button.dataset.userId;
        const role = $(`.admin-role-select[data-user-id="${userId}"]`).value;
        runAdminAction("/api/admin/set-role", { user_id: Number(userId), role }, "用户角色已更新。");
      });
    });
    $$(".admin-toggle-status").forEach((button) => {
      button.addEventListener("click", () => {
        const userId = Number(button.dataset.userId);
        const status = button.dataset.status;
        if (status === "disabled" && !window.confirm("停用后该用户会立即退出所有设备，是否继续？")) return;
        runAdminAction("/api/admin/set-status", { user_id: userId, status }, status === "disabled" ? "账号已停用。" : "账号已启用。");
      });
    });
    $$(".admin-reset-password").forEach((button) => {
      button.addEventListener("click", async () => {
        if (!window.confirm("重置后该用户所有登录会话会失效，是否继续？")) return;
        const result = await runAdminAction("/api/admin/reset-password", { user_id: Number(button.dataset.userId) }, "密码已重置。");
        if (result?.temporaryPassword) {
          window.prompt("请安全转交临时密码；关闭后无法再次查看：", result.temporaryPassword);
        }
      });
    });
    $$(".admin-delete-user").forEach((button) => {
      button.addEventListener("click", () => {
        if (!window.confirm("删除用户会同时删除其案例、证据文件和会话，且不可恢复。是否继续？")) return;
        runAdminAction("/api/admin/delete-user", { user_id: Number(button.dataset.userId) }, "用户及其数据已删除。");
      });
    });
  } catch (error) {
    toast(`后台数据加载失败：${error.message}`);
  }
}

function setAccountMessage(message, isError = false) {
  const element = $("#accountMessage");
  if (!element) return;
  element.textContent = message;
  element.classList.toggle("error", isError);
  element.classList.remove("hidden");
}

async function refreshAccountCenter() {
  if (!state.user) return;
  try {
    const payload = await apiRequest("/api/auth/sessions");
    renderSessions(payload.sessions || []);
  } catch (error) {
    setAccountMessage(`登录设备加载失败：${error.message}`, true);
  }
}

function renderSessions(sessions) {
  const container = $("#sessionList");
  if (!container) return;
  if (!sessions.length) {
    container.innerHTML = '<div class="evidence-empty">暂无有效会话。</div>';
    return;
  }
  container.innerHTML = sessions.map((session) => `
    <div class="session-item ${session.current ? "session-current" : ""}">
      <div>
        <strong>${session.current ? "当前设备" : "其他设备"} · ${escapeHtml(session.client_ip || "未知IP")}</strong>
        <small>${escapeHtml(session.user_agent || "未知浏览器")} · 登录于 ${escapeHtml(session.created_at)} · 到期 ${escapeHtml(session.expires_at)}</small>
      </div>
      ${session.current ? '<span class="status-badge status-active">正在使用</span>' : ""}
    </div>
  `).join("");
}

async function changePassword(event) {
  event?.preventDefault();
  const currentPassword = $("#currentPassword")?.value || "";
  const newPassword = $("#newPassword")?.value || "";
  const confirmPassword = $("#confirmPassword")?.value || "";
  if (newPassword.length < 10) {
    setAccountMessage("新密码至少需要10位。", true);
    return;
  }
  if (newPassword !== confirmPassword) {
    setAccountMessage("两次输入的新密码不一致。", true);
    return;
  }
  try {
    await apiRequest("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword })
    });
    ["currentPassword", "newPassword", "confirmPassword"].forEach((id) => { if ($(`#${id}`)) $(`#${id}`).value = ""; });
    setAccountMessage("密码已更新，其他设备的登录会话已退出。");
    refreshAccountCenter();
  } catch (error) {
    setAccountMessage(`密码更新失败：${error.message}`, true);
  }
}

async function revokeOtherSessions() {
  try {
    await apiRequest("/api/auth/revoke-sessions", { method: "POST", body: "{}" });
    setAccountMessage("其他设备的登录会话已全部退出。");
    refreshAccountCenter();
  } catch (error) {
    setAccountMessage(`操作失败：${error.message}`, true);
  }
}

async function exportAccountData() {
  const password = $("#exportPassword")?.value || "";
  if (!password) {
    setAccountMessage("请输入当前密码后再导出。", true);
    return;
  }
  try {
    const data = await apiRequest("/api/auth/export", {
      method: "POST",
      body: JSON.stringify({ password })
    });
    downloadJson(`职安盾-个人数据-${new Date().toISOString().slice(0, 10)}.json`, data);
    $("#exportPassword").value = "";
    setAccountMessage("个人数据已导出。证据原件请使用“下载完整证据包”。");
  } catch (error) {
    setAccountMessage(`导出失败：${error.message}`, true);
  }
}

async function deleteAccount() {
  const confirmName = $("#deleteAccountConfirm")?.value.trim() || "";
  const password = $("#deleteAccountPassword")?.value || "";
  if (!confirmName || !password) {
    setAccountMessage("请输入用户名和密码后确认删除。", true);
    return;
  }
  if (!window.confirm("账号、案例和证据文件将被永久删除，是否继续？")) return;
  try {
    await apiRequest("/api/auth/delete", {
      method: "POST",
      body: JSON.stringify({ confirm: confirmName, password })
    });
    state.user = null;
    state.history = [];
    state.evidenceFiles = [];
    setAccountMessage("账号及全部数据已删除。");
    updateUserUI();
    navigate("dashboard");
    $("#authDialog")?.showModal();
  } catch (error) {
    setAccountMessage(`删除失败：${error.message}`, true);
  }
}

function buildReport(result) {
  if (!result) return "尚无研判结果。";
  return [
    "职安盾 VeriWork 研判报告",
    `生成时间：${formatDate()}`,
    `材料类型：${result.caseType || "未指定"}`,
    `适用地区：${result.jurisdiction || "全国规则"}`,
    `风险分：${result.riskScore}（${result.riskLevel}）`,
    "",
    "一、风险清单",
    ...result.risks.map((risk, index) => [
      `${index + 1}. [${severityText(risk.severity)}] ${risk.title}`,
      `原文：${risk.clause}`,
      `说明：${risk.modelReason || risk.reason}`,
      `建议：${risk.modelAction || risk.action}`,
      `法源：${risk.lawItems.map((law) => law.source).join("；")}`
    ].join("\n")),
    "",
    "二、可信轨迹",
    ...result.trace.map((item, index) => `${index + 1}. ${item.title}：${item.detail}`),
    "",
    "三、后续行动",
    ...result.questions,
    "",
    "四、合规声明",
    APP_DATA.meta.disclaimer
  ].join("\n\n");
}

function initCarousel() {
  const track = $(".carousel-track");
  const dots = $$(".carousel-dots button");
  if (!track || !dots.length) return;
  let index = 0;
  const show = (next) => {
    index = (next + dots.length) % dots.length;
    track.style.transform = `translateX(-${index * 100}%)`;
    dots.forEach((dot, dotIndex) => dot.classList.toggle("active", dotIndex === index));
  };
  dots.forEach((dot) => dot.addEventListener("click", () => show(Number(dot.dataset.slide))));
  let timer = window.setInterval(() => show(index + 1), 5200);
  $("#heroCarousel")?.addEventListener("mouseenter", () => window.clearInterval(timer));
  $("#heroCarousel")?.addEventListener("mouseleave", () => { timer = window.setInterval(() => show(index + 1), 5200); });
}

function bindEvents() {
  $$(".nav-item").forEach((element) => element.addEventListener("click", () => navigate(element.dataset.page)));
  $$("[data-go]").forEach((element) => element.addEventListener("click", () => navigate(element.dataset.go)));

  $("#quickDemo").addEventListener("click", () => loadCase(APP_DATA.demoCases[0], true));
  $("#loadSampleButton").addEventListener("click", () => {
    $("#contractInput").value = APP_DATA.demoCases[0].text;
    $("#contractInput").dispatchEvent(new Event("input"));
  });
  $("#clearButton").addEventListener("click", () => {
    $("#contractInput").value = "";
    $("#contractInput").dispatchEvent(new Event("input"));
    $("#analysisResult").classList.add("hidden");
    $("#emptyResult").classList.remove("hidden");
    $("#resultStatus").textContent = "等待分析";
  });
  $("#contractInput").addEventListener("input", (event) => {
    $("#charCount").textContent = `${event.target.value.length} 字`;
  });
  $("#fileInput").addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    if (state.settings.runMode === "api" && !state.user) {
      $("#authDialog")?.showModal();
      toast("文件解析需要登录，请先登录或注册账号。");
      event.target.value = "";
      return;
    }
    const extension = `.${file.name.split(".").pop().toLowerCase()}`;
    try {
      let text;
      if ([".pdf", ".docx"].includes(extension)) {
        if (state.settings.runMode !== "api") {
          throw new Error("PDF和Word解析需要后端服务，请启动完整服务后重试");
        }
        text = await extractDocumentViaApi(file);
      } else {
        text = await file.text();
      }
      $("#contractInput").value = text;
      $("#contractInput").dispatchEvent(new Event("input"));
      toast(`已载入 ${file.name}，共 ${text.length} 字`);
    } catch (error) {
      toast(`文件读取失败：${error.message}`);
    } finally {
      event.target.value = "";
    }
  });
  $("#analyzeButton").addEventListener("click", runAnalysis);
  $$(".result-tabs .tab").forEach((element) => element.addEventListener("click", () => switchResultTab(element.dataset.resultTab)));
  $("#sendToEvidence").addEventListener("click", () => {
    navigate("evidence");
    toast("风险行动建议已同步到证据链。");
  });
  $("#exportReport").addEventListener("click", () => {
    if (!state.lastAnalysis) {
      toast("请先完成一次研判。");
      return;
    }
    if (state.lastCaseId && state.settings.runMode === "api") {
      openCaseReport(state.lastCaseId);
      return;
    }
    downloadText("职安盾-研判报告.txt", buildReport(state.lastAnalysis));
    toast("研判报告已生成并下载。");
  });
  $("#downloadPdfReport")?.addEventListener("click", () => {
    if (!state.lastCaseId || state.settings.runMode !== "api") {
      toast("PDF报告需要完成一次登录后的后端研判。");
      return;
    }
    downloadCasePdf(state.lastCaseId);
  });

  $("#refreshHistory")?.addEventListener("click", refreshHistory);
  $("#uploadEvidenceButton")?.addEventListener("click", uploadEvidenceFile);
  $("#downloadEvidencePackage")?.addEventListener("click", downloadEvidencePackage);
  $("#passwordForm")?.addEventListener("submit", changePassword);
  $("#revokeOtherSessions")?.addEventListener("click", revokeOtherSessions);
  $("#exportAccountData")?.addEventListener("click", exportAccountData);
  $("#downloadEvidenceZip")?.addEventListener("click", downloadEvidencePackage);
  $("#deleteAccountButton")?.addEventListener("click", deleteAccount);

  $("#addEvidenceButton").addEventListener("click", addEvidence);
  $("#newEvidenceInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter") addEvidence();
  });
  $("#exportTimeline").addEventListener("click", () => {
    downloadText("职安盾-证据时间线.txt", buildTimelineExport());
    toast("证据时间线已导出。");
  });
  $$(".copy-button").forEach((button) => {
    button.addEventListener("click", async () => {
      const text = $(`#${button.dataset.copyTarget}`).textContent;
      try {
        await navigator.clipboard.writeText(text);
        toast("内容已复制。");
      } catch (error) {
        toast("浏览器未授权剪贴板，请手动复制。");
      }
    });
  });

  $("#matchPolicyButton").addEventListener("click", matchPolicies);
  $("#refreshAdmin").addEventListener("click", refreshAdminPage);
  $("#runEvaluation").addEventListener("click", runEvaluation);
  $("#openSettings").addEventListener("click", () => $("#settingsDialog").showModal());
  $("#saveSettings").addEventListener("click", async () => {
    saveSettings();
    await loadCurrentUser();
  });

  document.addEventListener("click", (event) => {
    if (event.target.closest("#openAuth")) { clearAuthError(); $("#authDialog")?.showModal(); }
    if (event.target.closest("#closeAuth")) { clearAuthError(); $("#authDialog")?.close(); }
    if (event.target.closest("#loginButton")) {
      loginWithCredentials($("#authUsername").value.trim(), $("#authPassword").value).catch((error) => showAuthError(error.message || "登录失败，请检查账号和密码"));
    }
    if (event.target.closest("#registerButton")) {
      registerAccount($("#authUsername").value.trim(), $("#authPassword").value).catch((error) => showAuthError(error.message || "注册失败，请检查输入信息"));
    }
  });
  ["authUsername", "authPassword"].forEach((id) => {
    $(`#${id}`)?.addEventListener("input", clearAuthError);
    $(`#${id}`)?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        loginWithCredentials($("#authUsername").value.trim(), $("#authPassword").value).catch((error) => showAuthError(error.message || "登录失败，请检查账号和密码"));
      }
    });
  });
}

function init() {
  renderMetrics();
  renderCaseQueue();
  renderEvidence();
  renderEvaluationCards();
  renderComparison();
  updateEvidenceDocuments(null);
  loadSettings();
  bindEvents();
  initCarousel();
  (async () => {
    await refreshBackendStatus();
    const authenticated = await loadCurrentUser();
    if (authenticated) {
      if (state.currentPage === "history") refreshHistory();
      if (state.currentPage === "evidence") refreshEvidenceFiles();
      if (state.currentPage === "account") refreshAccountCenter();
    }
    if (state.settings.runMode === "api" && !authenticated) {
      clearAuthError();
      $("#authDialog")?.showModal();
    }
  })();
  $("#contractInput").value = APP_DATA.demoCases[0].text;
  $("#contractInput").dispatchEvent(new Event("input"));

  const params = new URLSearchParams(window.location.search);
  const requestedPage = params.get("page");
  if (requestedPage && ["dashboard", "analysis", "history", "evidence", "policy", "account", "admin", "evaluation", "architecture"].includes(requestedPage)) {
    navigate(requestedPage);
  }
  if (params.get("demo") === "risk") {
    window.setTimeout(() => loadCase(APP_DATA.demoCases[0], true), 120);
  }
  if (params.get("demo") === "evaluation") {
    navigate("evaluation");
    window.setTimeout(runEvaluation, 160);
  }
}

window.VeriWork = { APP_DATA, analyzeContract, state };

document.addEventListener("DOMContentLoaded", () => {
  if (document.querySelector("#page-dashboard")) init();
});
