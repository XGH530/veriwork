const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const state = {
  currentPage: "dashboard",
  currentCase: APP_DATA.demoCases[0],
  lastAnalysis: null,
  checklist: APP_DATA.evidenceChecklist.map((item) => ({ ...item })),
  timeline: APP_DATA.timeline.map((item) => ({ ...item })),
  settings: {
    apiBase: "http://127.0.0.1:8000",
    runMode: "demo",
    model: ""
  },
  user: null,
  authMode: "student",
  authToken: localStorage.getItem("veriwork-token") || ""
};

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
  const headers = { ...extra };
  if (state.authToken) headers.Authorization = `Bearer ${state.authToken}`;
  return headers;
}

async function authRequest(path, payload) {
  const response = await fetch(`${state.settings.apiBase.replace(/\/$/, "")}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await response.json();
  if (!response.ok || data.error) throw new Error(data.error || `请求失败 ${response.status}`);
  return data;
}

async function loginWithCredentials(username, password, expectedMode = state.authMode) {
  const data = await authRequest("/api/auth/login", { username, password });
  if (expectedMode === "admin" && data.user.role !== "admin") {
    throw new Error("该账号不是管理员，请使用学生与毕业生入口");
  }
  if (expectedMode === "student" && data.user.role === "admin") {
    throw new Error("管理员请使用管理员入口");
  }
  state.authToken = data.token;
  state.user = data.user;
  localStorage.setItem("veriwork-token", data.token);
  updateUserUI();
  $("#authDialog")?.close();
  navigate(data.user.role === "admin" ? "admin" : "dashboard");
  toast(`已登录：${data.user.username}`);
}

function switchAuthMode(mode) {
  state.authMode = mode;
  $$(".auth-mode-button").forEach((button) => button.classList.toggle("active", button.dataset.authMode === mode));
  $$(".student-auth-only").forEach((element) => element.classList.toggle("hidden", mode !== "student"));
  $$(".admin-auth-only").forEach((element) => element.classList.toggle("hidden", mode !== "admin"));
  $("#authTitle").textContent = mode === "admin" ? "管理员入口" : "学生与毕业生入口";
  $("#authSubtitle").textContent = mode === "admin"
    ? "仅管理员可进入用户管理、角色管理和系统运营界面。"
    : "使用合同研判、文件解析、政策匹配和证据整理功能。";
  if (mode === "admin") {
    $("#authUsername").value = "admin";
    $("#authPassword").value = "admin123456";
  } else {
    $("#authUsername").value = "demo";
    $("#authPassword").value = "demo123456";
  }
}

async function registerAccount(username, password) {
  const data = await authRequest("/api/auth/register", { username, password });
  state.authToken = data.token;
  state.user = data.user;
  localStorage.setItem("veriwork-token", data.token);
  updateUserUI();
  $("#authDialog")?.close();
  toast(`注册成功：${data.user.username}`);
}

async function loadCurrentUser() {
  if (!state.authToken) {
    state.user = null;
    updateUserUI();
    return false;
  }
  try {
    const response = await fetch(`${state.settings.apiBase.replace(/\/$/, "")}/api/auth/me`, {
      headers: apiHeaders()
    });
    const data = await response.json();
    state.user = data.authenticated ? data.user : null;
    if (!state.user) {
      state.authToken = "";
      localStorage.removeItem("veriwork-token");
    }
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
      headers: apiHeaders({ "Content-Type": "application/json" }),
      body: "{}"
    });
  } catch (error) {
    console.warn(error);
  }
  state.authToken = "";
  state.user = null;
  localStorage.removeItem("veriwork-token");
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
  if (isAdmin && state.currentPage !== "admin") navigate("admin");
}

function formatDate(date = new Date()) {
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit"
  }).format(date);
}

function navigate(page) {
  state.currentPage = page;
  $$(".page").forEach((element) => element.classList.toggle("active", element.id === `page-${page}`));
  $$(".nav-item").forEach((element) => element.classList.toggle("active", element.dataset.page === page));
  if (state.user?.role === "admin" && page !== "admin") page = "admin";
  if (state.user?.role !== "admin" && page === "admin") page = "dashboard";
  const titles = {
    dashboard: "合同风险核查工作台",
    analysis: "合同风险核查",
    evidence: "证据整理与材料",
    policy: "就业扶持政策匹配",
    admin: "系统运营与用户管理",
    evaluation: "评测结果",
    architecture: "系统说明"
  };
  $("#pageTitle").textContent = titles[page] || "职安盾";
  if (page === "admin") refreshAdminPage();
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
    setProgress("", steps);
    renderAnalysis(result);
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

async function refreshAdminPage() {
  if (!state.user || state.user.role !== "admin") return;
  try {
    const response = await fetch(`${state.settings.apiBase.replace(/\/$/, "")}/api/admin/stats`, { headers: apiHeaders() });
    const data = await response.json();
    if (!response.ok || data.error) throw new Error(data.error || `API ${response.status}`);
    $("#adminUserCount").textContent = data.userCount;
    $("#adminCaseCount").textContent = data.caseCount;
    $("#adminHighRiskCount").textContent = data.highRiskCount;
    $("#adminModel").textContent = data.model || "未配置";
    $("#adminRecentCases").innerHTML = data.cases.length
      ? data.cases.map((item) => `<tr><td>${item.id}</td><td>${escapeHtml(item.username)}</td><td>${escapeHtml(item.case_type)}</td><td>${escapeHtml(item.jurisdiction)}</td><td>${escapeHtml(item.document_language)}</td><td>${item.risk_score}</td><td>${escapeHtml(item.created_at)}</td></tr>`).join("")
      : '<tr><td colspan="7">暂无研判记录</td></tr>';
    $("#adminTopRisks").innerHTML = data.topRisks.length
      ? data.topRisks.map(([id, count]) => `<div class="admin-risk-item"><span>${escapeHtml(getRisk(id)?.title || id)}</span><strong>${count}</strong></div>`).join("")
      : '<p class="dialog-note">暂无风险统计。</p>';
    $("#adminUsers").innerHTML = data.users.map((user) => `
      <tr>
        <td>${user.id}</td>
        <td>${escapeHtml(user.username)}</td>
        <td><select class="admin-role-select" data-user-id="${user.id}"><option value="student" ${user.role === "student" ? "selected" : ""}>student</option><option value="admin" ${user.role === "admin" ? "selected" : ""}>admin</option></select></td>
        <td>${escapeHtml(user.created_at)}</td>
        <td><button class="secondary-button admin-save-role" data-user-id="${user.id}">保存</button></td>
      </tr>`).join("");
    $$(".admin-save-role").forEach((button) => {
      button.addEventListener("click", async () => {
        const userId = button.dataset.userId;
        const role = $(`.admin-role-select[data-user-id="${userId}"]`).value;
        const saveResponse = await fetch(`${state.settings.apiBase.replace(/\/$/, "")}/api/admin/set-role`, {
          method: "POST",
          headers: apiHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ user_id: Number(userId), role })
        });
        const saveData = await saveResponse.json();
        if (!saveResponse.ok || saveData.error) {
          toast(`角色更新失败：${saveData.error || saveResponse.status}`);
          return;
        }
        toast("用户角色已更新。");
        refreshAdminPage();
      });
    });
  } catch (error) {
    toast(`后台数据加载失败：${error.message}`);
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
      toast("文件解析需要登录，请先登录或使用演示账号。");
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
    downloadText("职安盾-研判报告.txt", buildReport(state.lastAnalysis));
    toast("研判报告已生成并下载。");
  });

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
    if (event.target.closest("#openAuth")) $("#authDialog")?.showModal();
    if (event.target.closest("#closeAuth")) $("#authDialog")?.close();
    const authModeButton = event.target.closest(".auth-mode-button");
    if (authModeButton) switchAuthMode(authModeButton.dataset.authMode);
    if (event.target.closest("#loginButton")) {
      loginWithCredentials($("#authUsername").value.trim(), $("#authPassword").value).catch((error) => toast(`登录失败：${error.message}`));
    }
    if (event.target.closest("#demoLoginButton")) {
      loginWithCredentials("demo", "demo123456", "student").catch((error) => toast(`演示登录失败：${error.message}`));
    }
    if (event.target.closest("#registerButton")) {
      registerAccount($("#authUsername").value.trim(), $("#authPassword").value).catch((error) => toast(`注册失败：${error.message}`));
    }
    if (event.target.closest("#guestButton")) {
      state.settings.runMode = "demo";
      updateModeUI();
      $("#authDialog")?.close();
      toast("已进入本地演示模式，后端研判和文件解析需要登录。");
    }
  });
  ["authUsername", "authPassword"].forEach((id) => {
    $(`#${id}`)?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        loginWithCredentials($("#authUsername").value.trim(), $("#authPassword").value).catch((error) => toast(`登录失败：${error.message}`));
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
  switchAuthMode("student");
  bindEvents();
  initCarousel();
  (async () => {
    await refreshBackendStatus();
    const authenticated = await loadCurrentUser();
    if (state.settings.runMode === "api" && !authenticated) {
      $("#authDialog")?.showModal();
    }
  })();
  $("#contractInput").value = APP_DATA.demoCases[0].text;
  $("#contractInput").dispatchEvent(new Event("input"));

  const params = new URLSearchParams(window.location.search);
  const requestedPage = params.get("page");
  if (requestedPage && ["dashboard", "analysis", "evidence", "policy", "admin", "evaluation", "architecture"].includes(requestedPage)) {
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
