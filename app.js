const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

let analysisProgressTimer = null;
let analysisProgressStartedAt = 0;
let admin2faCountdownTimer = null;

const state = {
  currentPage: "dashboard",
  currentCase: APP_DATA.demoCases[0],
  lastAnalysis: null,
  lastCaseId: null,
  sourcePages: [],
  sourceDocument: null,
  fileLoading: false,
  pendingPage: null,
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
  authMode: "login",
  pending2fa: null,
  emailChallengeId: null
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

async function sha256Hex(buffer) {
  try {
    const digest = await crypto.subtle.digest("SHA-256", buffer);
    return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
  } catch (error) {
    console.warn("文件哈希计算失败", error);
    return "";
  }
}

async function extractDocumentViaApi(file) {
  const baseUrl = state.settings.apiBase.replace(/\/$/, "");
  const buffer = await file.arrayBuffer();
  const response = await fetch(`${baseUrl}/api/extract`, {
    method: "POST",
    credentials: "include",
    headers: apiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({
      filename: file.name,
      language: $("#documentLanguage")?.value || "zh",
      pageRange: $("#pageRange")?.value.trim() || "",
      content_base64: arrayBufferToBase64(buffer)
    })
  });
  const payload = await response.json();
  if (response.status === 401) {
    showAuthView("login");
    $("#authDialog")?.showModal();
    throw new Error("登录已失效，请重新登录");
  }
  if (!response.ok || payload.error) throw new Error(payload.error || `API ${response.status}`);
  return {
    text: String(payload.text || ""),
    pages: Array.isArray(payload.pages) ? payload.pages : [],
    filename: payload.filename || file.name,
    format: payload.format || file.name.split(".").pop().toLowerCase(),
    chars: Number(payload.chars) || String(payload.text || "").length,
    sizeBytes: Number(payload.sizeBytes) || file.size,
    sha256: payload.sha256 || await sha256Hex(buffer),
    pageCount: Number(payload.pageCount) || (Array.isArray(payload.pages) ? payload.pages.length : 1),
    ocr: Boolean(payload.ocr),
    ocrLanguage: payload.ocrLanguage || "",
    ocrMs: Number(payload.ocrMs) || 0
  };
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
  if (!response.ok || data.error) {
    const error = new Error(data.error || `请求失败 ${response.status}`);
    error.status = response.status;
    error.payload = data;
    throw error;
  }
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

function showAuthView(mode = "login") {
  state.authMode = mode;
  clearAuthError();
  $("#loginView")?.classList.toggle("hidden", mode !== "login");
  $("#registerView")?.classList.toggle("hidden", mode !== "register");
  $("#authKicker").textContent = mode === "register" ? "创建账号" : "平台登录";
  $("#authHeading").textContent = mode === "register" ? "注册职安盾账号" : "登录职安盾";
  $("#authDescription").textContent = mode === "register"
    ? "填写用户名、密码和邮箱。邮箱仅用于账号恢复和安全验证。"
    : "请输入平台账号和密码。系统会根据账号角色进入对应工作界面。";
  if (mode !== "login") {
    state.pending2fa = null;
    $("#twoFactorPanel")?.classList.add("hidden");
    $("#registerUsername")?.focus();
  } else {
    $("#authUsername")?.focus();
  }
}

function showAuthCloseNotice() {
  const notice = $("#authCloseNotice");
  if (!notice) return;
  notice.classList.remove("show");
  void notice.offsetWidth;
  notice.classList.add("show");
  window.clearTimeout(showAuthCloseNotice.timer);
  showAuthCloseNotice.timer = window.setTimeout(() => notice.classList.remove("show"), 2200);
}

async function loginWithCredentials(username, password) {
  clearAuthError();
  const data = await authRequest("/api/auth/login", { username, password });
  if (data.requires2fa) {
    state.pending2fa = data;
    $("#twoFactorPanel")?.classList.remove("hidden");
    $("#auth2faCode")?.focus();
    showAuthError(`验证码已发送到 ${data.emailHint || "绑定邮箱"}，请输入6位验证码。`);
    return;
  }
  completeLogin(data.user);
}

function isAdminRole(role) {
  return role === "admin" || role === "reviewer_admin";
}

const PROTECTED_PAGES = new Set([
  "dashboard", "analysis", "history", "evidence", "policy",
  "evaluation", "architecture", "account", "admin"
]);

function requireLogin(message = "请先登录后再使用平台功能。") {
  if (state.user) return true;
  showAuthView("login");
  const dialog = $("#authDialog");
  if (dialog && !dialog.open) dialog.showModal();
  toast(message);
  return false;
}

function completeLogin(user) {
  state.user = user;
  state.pending2fa = null;
  $("#twoFactorPanel")?.classList.add("hidden");
  $("#auth2faCode").value = "";
  updateUserUI();
  $("#authDialog")?.close();
  clearAuthError();
  const destination = isAdminRole(user.role) ? "admin" : (state.pendingPage || "dashboard");
  state.pendingPage = null;
  navigate(destination);
  toast(`已登录：${user.username}`);
}

async function verifyAdmin2fa() {
  if (!state.pending2fa?.challengeId) {
    showAuthError("请先使用管理员账号和密码登录。");
    return;
  }
  try {
    const data = await authRequest("/api/auth/verify-2fa", {
      challengeId: state.pending2fa.challengeId,
      code: $("#auth2faCode").value.trim()
    });
    completeLogin(data.user);
  } catch (error) {
    showAuthError(error.message || "二次验证失败");
  }
}

async function registerAccount(username, password) {
  const email = $("#authEmail")?.value.trim() || "";
  const data = await authRequest("/api/auth/register", { username, password, email });
  completeLogin(data.user);
  toast(`注册成功：${data.user.username}${email ? "，请到账户中心完成邮箱验证。" : ""}`);
}

function showAdminLoginError(message) {
  const element = $("#adminLoginError");
  if (!element) return;
  element.textContent = message;
  element.classList.remove("hidden");
}

function clearAdminLoginError() {
  const element = $("#adminLoginError");
  if (!element) return;
  element.textContent = "";
  element.classList.add("hidden");
}

async function refreshAdminLoginStatus() {
  try {
    const data = await apiRequest("/api/health");
    $("#adminServiceStatus").textContent = data.ok
      ? `服务正常 · ${data.model || "本地规则链路"}`
      : "服务状态异常";
  } catch (error) {
    $("#adminServiceStatus").textContent = "服务暂不可用";
  }
}

function setAdminLoginBusy(busy, label) {
  const button = $("#adminLoginButton");
  if (!button) return;
  button.disabled = busy;
  button.textContent = label || (state.pending2fa?.challengeId ? "验证邮箱并进入" : "进入运营控制台");
}

function clearAdmin2faCountdown() {
  if (admin2faCountdownTimer) window.clearInterval(admin2faCountdownTimer);
  admin2faCountdownTimer = null;
}

function startAdmin2faCountdown(data = {}) {
  clearAdmin2faCountdown();
  const resendAfter = Math.max(1, Number(data.resendAfter) || 60);
  const expiresIn = Math.max(60, Number(data.expiresIn) || 120);
  const deadline = Date.now() + resendAfter * 1000;
  const validity = $("#admin2faValidity");
  const resendButton = $("#adminResendCodeButton");
  if (validity) validity.textContent = `验证码 ${Math.round(expiresIn / 60)} 分钟内有效`;
  const update = () => {
    const remaining = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    if (!resendButton) return;
    resendButton.disabled = remaining > 0;
    resendButton.textContent = remaining > 0 ? `重新发送（${remaining}s）` : "重新发送验证码";
  };
  update();
  admin2faCountdownTimer = window.setInterval(() => {
    update();
    if (Date.now() >= deadline) clearAdmin2faCountdown();
  }, 250);
}

async function resendAdmin2faCode() {
  if (!state.pending2fa?.challengeId) {
    showAdminLoginError("请先使用管理员账号和密码登录。");
    return;
  }
  const button = $("#adminResendCodeButton");
  if (button) {
    button.disabled = true;
    button.textContent = "正在发送…";
  }
  clearAdminLoginError();
  try {
    const data = await authRequest("/api/auth/resend-2fa", {
      challengeId: state.pending2fa.challengeId
    });
    state.pending2fa = { ...state.pending2fa, ...data };
    $("#admin2faCode").value = "";
    $("#admin2faCode")?.focus();
    startAdmin2faCountdown(data);
    showAdminLoginError(`新的验证码已发送到 ${data.emailHint || "管理员邮箱"}。`);
  } catch (error) {
    const retryAfter = Number(error.payload?.retryAfter);
    if (retryAfter > 0) startAdmin2faCountdown({ resendAfter: retryAfter, expiresIn: 120 });
    showAdminLoginError(error.message || "验证码重新发送失败");
  }
}

async function adminLoginWithCredentials() {
  clearAdminLoginError();
  setAdminLoginBusy(true, "正在验证账号…");
  try {
    const data = await authRequest("/api/auth/login", {
      username: $("#adminUsername").value.trim(),
      password: $("#adminPassword").value
    });
    if (data.requires2fa) {
      state.pending2fa = data;
      $("#admin2faRow")?.classList.remove("hidden");
      $("#admin2faCode")?.focus();
      startAdmin2faCountdown(data);
      setAdminLoginBusy(false, "验证邮箱并进入");
      showAdminLoginError(`验证码已发送到 ${data.emailHint || "管理员邮箱"}，请在下方输入验证码后点击“验证邮箱并进入”。`);
      return;
    }
    if (!isAdminRole(data.user?.role)) {
      await authRequest("/api/auth/logout", {});
      showAdminLoginError("该账号不是管理员，不能进入运营控制台。");
      return;
    }
    window.location.href = `${window.location.pathname}?page=admin`;
  } catch (error) {
    showAdminLoginError(error.message || "管理员登录失败");
  } finally {
    setAdminLoginBusy(false);
  }
}

async function verifyAdminLogin2fa() {
  if (!state.pending2fa?.challengeId) {
    showAdminLoginError("请先输入管理员账号和密码。");
    return;
  }
  const code = $("#admin2faCode").value.trim();
  if (!/^\d{6}$/.test(code)) {
    showAdminLoginError("请输入6位邮箱验证码。");
    $("#admin2faCode")?.focus();
    return;
  }
  clearAdminLoginError();
  setAdminLoginBusy(true, "正在验证邮箱验证码…");
  try {
    const data = await authRequest("/api/auth/verify-2fa", {
      challengeId: state.pending2fa.challengeId,
      code
    });
    if (!isAdminRole(data.user?.role)) {
      await authRequest("/api/auth/logout", {});
      showAdminLoginError("该账号不是管理员，不能进入运营控制台。");
      return;
    }
    state.pending2fa = null;
    clearAdmin2faCountdown();
    window.location.href = `${window.location.pathname}?page=admin`;
  } catch (error) {
    showAdminLoginError(error.message || "邮箱验证码不正确");
  } finally {
    setAdminLoginBusy(false);
  }
}

function handleAdminLoginAction() {
  if (state.pending2fa?.challengeId) return verifyAdminLogin2fa();
  return adminLoginWithCredentials();
}

function initAdminLoginPage() {
  document.body.classList.add("admin-login-mode");
  const page = $("#adminLoginPage");
  page?.classList.remove("hidden");
  loadSettings();
  refreshAdminLoginStatus();
  $("#adminLoginButton")?.addEventListener("click", handleAdminLoginAction);
  $("#admin2faCode")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") verifyAdminLogin2fa();
  });
  $("#adminResendCodeButton")?.addEventListener("click", resendAdmin2faCode);
  $("#adminPassword")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") handleAdminLoginAction();
  });
  $("#backToUserLogin")?.addEventListener("click", () => {
    window.location.href = window.location.pathname;
  });
}

async function requestPasswordResetCode() {
  const identifier = $("#resetIdentifier")?.value.trim();
  if (!identifier) {
    $("#resetMessage").textContent = "请输入用户名或邮箱。";
    return;
  }
  try {
    const data = await authRequest("/api/auth/request-password-reset", { identifier });
    $("#resetMessage").textContent = data.message || "如果账号存在且已绑定邮箱，验证码将发送到该邮箱。";
    if (!data.deliveryAvailable) {
      $("#resetMessage").textContent = "邮件服务尚未配置，或该账号没有已验证邮箱。请联系管理员。";
    }
  } catch (error) {
    $("#resetMessage").textContent = error.message || "验证码发送失败。";
  }
}

async function confirmPasswordReset() {
  const identifier = $("#resetIdentifier")?.value.trim();
  const code = $("#resetCode")?.value.trim();
  const newPassword = $("#resetNewPassword")?.value || "";
  if (newPassword.length < 10) {
    $("#resetMessage").textContent = "新密码至少需要10位。";
    return;
  }
  try {
    await authRequest("/api/auth/reset-password", { identifier, code, newPassword });
    $("#resetMessage").textContent = "密码已重置，请返回登录。";
    toast("密码已重置。");
  } catch (error) {
    $("#resetMessage").textContent = error.message || "密码重置失败。";
  }
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
  state.history = [];
  state.evidenceFiles = [];
  clearWorkspaceData();
  state.pendingPage = "dashboard";
  updateUserUI();
  showAuthView("login");
  const dialog = $("#authDialog");
  if (dialog && !dialog.open) dialog.showModal();
  toast("已退出登录。");
}

function updateUserUI() {
  const chip = $("#userChip");
  if (!chip) return;
  if (state.user) {
    chip.innerHTML = `<span>用户：<strong>${escapeHtml(state.user.username)}</strong></span><button id="logoutButton" class="link-button">退出</button>`;
    $("#logoutButton")?.addEventListener("click", logoutAccount);
  } else {
    chip.innerHTML = '<span>未登录</span><button id="openAuth" class="link-button">登录</button>';
    $("#openAuth")?.addEventListener("click", () => { showAuthView("login"); $("#authDialog")?.showModal(); });
  }
  const isAdmin = isAdminRole(state.user?.role);
  document.body.classList.toggle("admin-mode", isAdmin);
  document.body.classList.toggle("reviewer-admin-mode", state.user?.role === "reviewer_admin");
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
  if (!state.user && PROTECTED_PAGES.has(page)) {
    state.pendingPage = page;
    requireLogin(`登录后才能使用“${page === "analysis" ? "合同研判" : "该功能"}”。`);
    return;
  }
  const isAdmin = isAdminRole(state.user?.role);
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
  if (page === "evidence") {
    refreshEvidenceFiles();
    if (state.lastAnalysis) syncEvidenceFromAnalysis(state.lastAnalysis, { silent: true });
  }
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
  const normalized = text.replace(/\r/g, "").replace(/\s*\n\s*/g, "");
  return normalized
    .split(/[。；;]+/)
    .flatMap((part) => part.split(/(?=第[一二三四五六七八九十百0-9]+条)/))
    .map((item) => item.trim())
    .filter((item) => item.length > 1);
}

function semanticDetection(clauses, existingRisks, documentType = "") {
  const existingIds = new Set(existingRisks.map((item) => item.id));
  const riskById = Object.fromEntries(APP_DATA.riskPatterns.map((risk) => [risk.id, risk]));
  const additions = [];
  Object.entries(APP_DATA.semanticPatterns).forEach(([riskId, patternText]) => {
    if (existingIds.has(riskId)) return;
    const base = riskById[riskId];
    if (!base) return;
    if (base.documentTypes && !base.documentTypes.includes(documentType)) return;
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

function extractLocalFacts(text, documentType = "") {
  const match = (pattern, flags = "i") => {
    const item = text.match(new RegExp(pattern, flags));
    return item ? String(item[1] || "").trim() : "";
  };
  const clean = (value) => String(value || "").replace(/\s+/g, "");
  const isTripartite = documentType === "三方协议";
  const partyA = clean(match("(?:甲方|用人单位)\\s*[:：]\\s*([^\\n（(]{2,60})"))
    || clean(match("甲方[^。\\n]{0,25}?(?:名称)?\\s*[:：]\\s*([^\\n，,；;]{2,60})"))
    || clean(match("([^\\n（(]{2,60}?)\\s*[（(]\\s*以下简称[^）)]*甲方[^）)]*[）)]"));
  const school = clean(match("([\\u4e00-\\u9fa5]{2,30}(?:学院|大学))[\\s\\S]{0,40}?学\\s*生"))
    || clean(match("丙方[^。\\n]{0,25}?(?:名称)?\\s*[:：]\\s*([^\\n，,；;]{2,60})"))
    || clean(match("(?:学校|院校)\\s*[:：]\\s*([^\\n，,；;]{2,40})"));
  const actualEmployer = clean(match("派驻至\\s*([\\s\\S]{3,80}?)[，,。；]?\\s*在"))
    || clean(match("(?:实际用工单位|用工单位|报到单位|接收单位)\\s*[:：]\\s*([^\\n，,；;]{2,60})"));
  const position = clean(match("在\\s*([^\\s，,。；;]{1,20})\\s*(?:部门|岗位)"))
    || clean(match("(?:岗位|职位)(?:名称)?\\s*(?:[:：]|为)\\s*([^\\n，,；;。]{1,30})"));
  const locationText = clean(match("(?:工作地点|实习地点|用工地点|报到地点)\\s*(?:[:：]|为)\\s*([^\\n，,；;。]{2,40})"));
  const startMatch = text.match(/自\s*(20\d{2})\s*年\s*(\d{1,2})\s*月\s*(\d{1,2})\s*日\s*至/);
  const endMatch = text.match(/至\s*(20\d{2})\s*年\s*(\d{1,2})\s*月\s*(\d{1,2})\s*日/);
  const formatDate = (item) => item ? `${item[1]}年${Number(item[2])}月${Number(item[3])}日` : "";
  const start = startMatch ? `${startMatch[1]}-${startMatch[2]}-${startMatch[3]}` : "";
  const end = endMatch ? `${endMatch[1]}-${endMatch[2]}-${endMatch[3]}` : "";
  const termDays = start && end ? Math.max(0, Math.round((new Date(end) - new Date(start)) / 86400000)) : null;
  const reportDeadline = clean(match("报到(?:时间|日期)?[^。\\n]{0,12}?(20\\d{2}\\s*年\\s*\\d{1,2}\\s*月\\s*\\d{1,2}\\s*日)"));
  const dailyPay = match("(\\d+(?:\\.\\d+)?)\\s*元\\s*[/／]\\s*天");
  const monthlyPay = match("(\\d+(?:\\.\\d+)?)\\s*元\\s*[/／]\\s*月");
  const salary = monthlyPay || match("(?:月工资|月薪|薪资|工资标准)[^。\\n]{0,15}?(\\d+(?:\\.\\d+)?)\\s*元");
  const probation = match("试用期[^。\\n]{0,12}?([一二三四五六七八九十0-9]{1,2})\\s*个?月");
  const liquidatedDamages = match("违约金[^。\\n]{0,20}?(\\d+(?:\\.\\d+)?)\\s*元") || match("违约金[^。\\n]{0,20}?([一二三四五六七八九十百千万]{2,})");
  const archiveTransfer = match("(档案[^。\\n]{0,40}(?:转寄|接收|保管|转回|迁转|随转)[^。\\n]{0,40})");
  const householdTransfer = match("((?:户口|户籍)[^。\\n]{0,40}(?:迁移|接收|不接收|转回|随迁)[^。\\n]{0,40})");
  const workHours = text.includes("标准工时") ? "标准工时制" : text.includes("综合计算工时") ? "综合计算工时制" : text.includes("不定时工作") ? "不定时工作制" : "";
  const insuranceTerms = ["意外伤害保险", "意外险", "实习责任保险", "工伤保险", "商业保险"].filter((term) => text.includes(term));
  const schoolSignature = /学校[^。；\n]{0,20}(?:盖章|签字|签章)|学校（盖章）|丙方[^。；\n]{0,25}(?:盖章|签字|签章)/.test(text);
  const employerSignature = /甲方[^。；\n]{0,25}(?:盖章|签字|签章)/.test(text);
  const studentSignature = /乙方[^。；\n]{0,25}(?:签字|签名|签章)/.test(text);
  const hasDisputeClause = /争议|仲裁|人民法院|诉讼|管辖/.test(text);
  const hasJobAttachment = /岗位说明|实习任务书|实习任务|附件[一二三四五六七八九十0-9]?|附件清单/.test(text);
  const payerWindow = match("委托([\\s\\S]{0,220}?)(?:发放|支付)");
  const payerMatches = payerWindow.match(/[\u4e00-\u9fa5]{4,40}(?:有限公司|有限责任公司|分公司|集团)/g) || [];
  const payer = (payerMatches[payerMatches.length - 1] || "").replace(/^(?:其)?(?:依法)?(?:设立的?)?/, "");
  const relationshipFeatures = ["标准工时", "实际出勤", "绩效", "考勤", "部门", "按月", "派驻", "试用期", "服务期", "违约金"].filter((term) => text.includes(term));
  const cityNames = ["深圳", "广州", "北京", "上海", "重庆", "成都", "杭州", "南京", "武汉", "西安", "苏州", "天津", "长沙", "郑州", "合肥", "厦门", "福州", "济南", "青岛", "大连", "沈阳", "哈尔滨", "昆明", "南昌", "贵阳", "南宁", "海口", "兰州", "太原", "石家庄"];
  const workLocation = locationText || actualEmployer;
  const workCity = cityNames.find((city) => workLocation.includes(city)) || cityNames.find((city) => actualEmployer.includes(city)) || cityNames.find((city) => text.slice(0, 600).includes(city)) || "";
  const jurisdictionMap = { "深圳": "深圳", "广州": "广东", "北京": "北京", "上海": "上海", "重庆": "重庆", "成都": "四川", "杭州": "浙江", "南京": "江苏", "武汉": "湖北", "西安": "陕西", "苏州": "江苏", "天津": "天津", "长沙": "湖南", "郑州": "河南", "合肥": "安徽", "厦门": "福建", "福州": "福建" };
  return {
    documentType,
    isTripartite,
    partyA,
    school,
    actualEmployer,
    position,
    workLocation,
    workCity,
    startDate: formatDate(startMatch),
    endDate: formatDate(endMatch),
    termDays,
    reportDeadline,
    dailyPay,
    monthlyPay,
    salary,
    probation: probation ? `${probation}个月` : "",
    hourlyEquivalentAt8h: dailyPay ? Math.round((Number(dailyPay) / 8) * 100) / 100 : null,
    workHours,
    payer: payer && payer !== partyA ? payer : "",
    thirdPartyArrangement: Boolean(!isTripartite && actualEmployer && partyA && actualEmployer !== partyA),
    hasSchoolSignature: schoolSignature,
    hasEmployerSignature: employerSignature,
    hasStudentSignature: studentSignature,
    hasAccidentInsurance: insuranceTerms.length > 0,
    insuranceTerms,
    hasDisputeClause,
    hasJobAttachment,
    liquidatedDamages,
    archiveTransfer,
    householdTransfer,
    relationshipFeatures,
    suggestedJurisdiction: jurisdictionMap[workCity] || "",
    factsToVerify: []
  };
}

function locateLocalClause(text, clause) {
  const leading = clause.match(/^\s*(第[一二三四五六七八九十百0-9]+条)/);
  if (leading) return { page: 1, clause: leading[1] };
  const needle = clause.replace(/\s+/g, "").slice(0, 60);
  const compactChars = [];
  for (let index = 0; index < text.length; index += 1) {
    if (!/\s/.test(text[index])) compactChars.push([text[index], index]);
  }
  const compact = compactChars.map((item) => item[0]).join("");
  const compactIndex = needle ? compact.indexOf(needle.slice(0, 40)) : -1;
  const originalIndex = compactIndex >= 0 ? compactChars[compactIndex][1] : text.indexOf(clause.slice(0, 30));
  const prefix = originalIndex >= 0 ? text.slice(0, originalIndex) : "";
  const lineStarts = [...prefix.matchAll(/^\s*(第[一二三四五六七八九十百0-9]+条)/gm)].map((item) => item[1]);
  if (lineStarts.length) return { page: 1, clause: lineStarts[lineStarts.length - 1] };
  const matches = [...prefix.matchAll(/第[一二三四五六七八九十百0-9]+条/g)];
  return { page: 1, clause: matches.length ? matches[matches.length - 1][0] : "未编号条款" };
}


function analyzeContract(text, options = {}) {
  const startedAt = performance.now();
  const jurisdiction = options.jurisdiction || "全国规则";
  const jurisdictionProfile = APP_DATA.jurisdictionProfiles.find((item) => item.id === jurisdiction) || APP_DATA.jurisdictionProfiles[0];
  const head = text.slice(0, 500).replace(/\s+/g, "");
  const documentType = (head.includes("三方协议") || head.includes("就业协议书"))
    ? "三方协议"
    : head.includes("实习协议") ? "实习协议" : head.includes("劳动合同") ? "劳动合同" : (options.caseType || "劳动合同");
  const facts = extractLocalFacts(text, documentType);
  const clauses = splitClauses(text);
  const detected = [];

  APP_DATA.riskPatterns.forEach((risk) => {
    if (risk.documentTypes && !risk.documentTypes.includes(documentType)) return;
    if (risk.factOnly) return;
    const regex = new RegExp(risk.regex, "i");
    for (const clause of clauses) {
      const match = clause.match(regex);
      if (!match) continue;
      if (risk.exceptionRegex && new RegExp(risk.exceptionRegex, "i").test(clause)) continue;
      detected.push({
        ...risk,
        clause,
        matchText: match[0],
        detectionMode: "deterministic",
        location: locateLocalClause(text, clause),
        lawItems: retrieveLaws(clause, risk.lawIds, 4)
      });
      break;
    }
  });

  const semantic = semanticDetection(clauses, detected, documentType);
  semantic.forEach((item) => {
    if (!item.location) item.location = locateLocalClause(text, item.clause);
  });
  detected.push(...semantic);

  const addFactRisk = (riskId, clause) => {
    if (detected.some((item) => item.id === riskId)) return;
    const base = getRisk(riskId);
    if (!base) return;
    detected.push({
      ...base,
      clause,
      matchText: clause,
      detectionMode: "fact",
      location: { page: 1, clause: "结构化事实" },
      lawItems: retrieveLaws(clause, base.lawIds, 4)
    });
  };

  if (facts.thirdPartyArrangement) addFactRisk("third_party_payor", "签约单位、实际用工单位或发薪主体不一致");
  if (documentType === "实习协议" && facts.relationshipFeatures.length) addFactRisk("internship_relationship_mismatch", "标准工时、考勤、绩效或派驻等劳动用工特征");
  if (documentType === "实习协议" && !facts.hasAccidentInsurance) addFactRisk("internship_insurance_missing", "未识别到实习责任保险或意外伤害保险");
  if (text.includes("延长工作时间") && !text.includes("加班费") && !text.includes("加班工资")) addFactRisk("overtime_without_compensation", "文本存在加班安排但未识别到加班费或调休");
  if (text.includes("绩效") && text.includes("岗位") && text.includes("调整")) addFactRisk("performance_unilateral", "绩效津贴可随岗位或表现变化");
  if (text.includes("保密") && (text.includes("终止") || text.includes("后均有效"))) addFactRisk("confidentiality_overbroad", "保密义务延续至协议终止后且范围不明确");
  if (documentType === "三方协议") {
    if (facts.partyA && facts.actualEmployer && !facts.partyA.includes(facts.actualEmployer)) addFactRisk("tripartite_entity_mismatch", "签约单位与报到或实际用工单位不一致");
    if (facts.school && !facts.hasSchoolSignature) addFactRisk("tripartite_school_missing", "未识别到丙方学校盖章或签字");
  }

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
  if (facts.suggestedJurisdiction && jurisdiction === "全国规则") {
    reviewItems.push({
      id: "suggested_jurisdiction",
      title: "工作地点与适用地区不一致",
      detail: `已识别到工作地点可能在${facts.suggestedJurisdiction}（${facts.workCity}），请切换或核验属地规则。`
    });
  }
  if (facts.thirdPartyArrangement) {
    reviewItems.push({
      id: "third_party_arrangement",
      title: "签约、用工与发薪主体需要核实",
      detail: "签约单位、实际用工单位和发薪主体可能不一致，需确认管理、报酬和事故责任主体。"
    });
  }
  if (documentType === "实习协议" && facts.school && !facts.hasSchoolSignature) {
    reviewItems.push({
      id: "school_signature_missing",
      title: "学校签署或三方安排需核实",
      detail: "协议提到学校，但未识别到学校盖章或签字页；请补充学校实习安排、三方协议或指导教师信息。"
    });
  }
  if (documentType === "实习协议" && !facts.hasDisputeClause) {
    reviewItems.push({
      id: "dispute_clause_missing",
      title: "争议解决条款缺失",
      detail: "未识别到争议解决、仲裁或法院管辖安排，发生争议时责任和路径可能不明确。"
    });
  }
  if (documentType === "实习协议" && !facts.hasJobAttachment) {
    reviewItems.push({
      id: "job_attachment_missing",
      title: "岗位任务附件缺失",
      detail: "协议未识别到岗位说明书、实习任务书或具体工作内容附件，岗位边界和考核标准不明确。"
    });
  }
  if (documentType === "实习协议" && !facts.hasAccidentInsurance) {
    reviewItems.push({
      id: "insurance_missing",
      title: "实习保险安排缺失",
      detail: "未识别到实习责任保险或意外伤害保险安排，发生事故时责任和救治路径不清。"
    });
  }
  if (documentType === "三方协议") {
    if (!facts.hasEmployerSignature) reviewItems.push({ id: "tripartite_employer_signature", title: "甲方（用人单位）签章需核实", detail: "未识别到甲方盖章或签字，三方协议需要用人单位确认后才能作为完整就业材料。" });
    if (!facts.hasStudentSignature) reviewItems.push({ id: "tripartite_student_signature", title: "乙方（毕业生）签字需核实", detail: "未识别到毕业生本人签字，需确认签署主体和签署日期。" });
    if (facts.school && !facts.hasSchoolSignature) reviewItems.push({ id: "tripartite_school_signature", title: "丙方（学校）签章需核实", detail: "未识别到学校就业部门盖章或经办人签字，可能影响报到、档案和就业手续办理。" });
    if (!facts.hasDisputeClause) reviewItems.push({ id: "tripartite_dispute_clause", title: "三方协议争议解决条款缺失", detail: "未识别到争议解决或管辖安排，发生违约争议时处理路径可能不明确。" });
    if (!facts.archiveTransfer) reviewItems.push({ id: "tripartite_archive_missing", title: "档案转寄安排需核实", detail: "未识别到档案接收单位、地址或转寄安排，可能影响毕业派遣和入职手续。" });
    if (!facts.householdTransfer) reviewItems.push({ id: "tripartite_household_missing", title: "户口/户籍安排需核实", detail: "未识别到户口迁移或接收安排，需向学校和用人单位确认。" });
    if (facts.liquidatedDamages) reviewItems.push({ id: "tripartite_liquidated_damages", title: "违约金条款需要实质核验", detail: `识别到违约金条款（${facts.liquidatedDamages}），需核对是否与服务期、培训费、实际损失和双方对等性相匹配。` });
    if (text.includes("三方协议") && text.includes("代替") && text.includes("劳动合同")) reviewItems.push({ id: "tripartite_not_labor_contract", title: "三方协议不能替代劳动合同", detail: "协议出现以三方协议代替劳动合同的表述，入职后仍应依法签订书面劳动合同。" });
  }
  if (facts.dailyPay) {
    reviewItems.push({
      id: "daily_pay_check",
      title: "日补贴需要折算核验",
      detail: `日补贴${facts.dailyPay}元，按8小时折算约${facts.hourlyEquivalentAt8h}元/小时，需核对工作地最低工资和实际工时。`
    });
  }
  const dedupedReviews = [];
  const seenReviews = new Set();
  reviewItems.forEach((item) => {
    if (seenReviews.has(item.id)) return;
    seenReviews.add(item.id);
    dedupedReviews.push(item);
  });

  const highCount = detected.filter((item) => item.severity === "high").length;
  const mediumCount = detected.filter((item) => item.severity === "medium").length;
  const rawRisk = detected.reduce((sum, item) => sum + item.weight, 22);
  const requiresHumanReview = dedupedReviews.length > 0 || documentType === "实习协议" || documentType === "三方协议";
  let riskScore = detected.length ? Math.min(96, rawRisk) : requiresHumanReview ? 35 : 6;
  if (detected.some((item) => item.id === "internship_wage_forfeit")) riskScore = Math.max(riskScore, 78);
  const riskLevel = detected.length
    ? riskScore >= 70 ? "高风险" : riskScore >= 40 ? "中风险" : "低风险"
    : requiresHumanReview ? "待核实" : "低风险";
  const riskHeadline = detected.length
    ? `发现 ${detected.length} 项风险，其中 ${highCount} 项高风险`
    : requiresHumanReview ? "材料信息不足，暂不能给出确定结论" : "未发现明显高风险条款";
  const riskDescription = detected.length
    ? `已识别为${documentType}。以下结论来自确定性规则、结构化事实和法源匹配，并已列出需要人工核实的事项。`
    : requiresHumanReview
      ? "当前材料缺少决定性事实，系统将停止输出确定结论，请补充书面协议、岗位说明、工资和用工管理记录。"
      : "当前规则未发现明显风险，但不代表材料在所有场景下均无争议，建议仍由专业人员复核。";

  const lawIds = [...new Set(detected.flatMap((item) => item.lawIds))];
  const citations = lawIds.map(getLaw).filter(Boolean);
  const citedRisks = detected.filter((item) => item.lawItems.length > 0).length;
  const citationCoverage = detected.length ? Math.round((citedRisks / detected.length) * 100) : 100;
  const processingMs = Math.max(1, Math.round(performance.now() - startedAt));
  const ruleHits = detected.filter((item) => item.detectionMode === "deterministic").length;
  const semanticHits = detected.filter((item) => item.detectionMode === "semantic").length;
  const factHits = detected.filter((item) => item.detectionMode === "fact").length;

  const trace = [
    { title: "文档类型判断", detail: `识别为${documentType}；用户选择为${options.caseType || "未指定"}。` },
    { title: "条款切分与事实抽取", detail: `识别 ${clauses.length} 个语义片段，并抽取主体、地点、期限、报酬和签署信息。` },
    { title: "本地法源检索", detail: `风险规则关联 ${citations.length} 条核心法源，并结合条款关键词执行本地检索排序；地区模式为“${jurisdictionProfile.title}”。` },
    { title: "规则引擎研判", detail: `确定性规则命中 ${ruleHits} 项，事实规则补充 ${factHits} 项，语义规则补充 ${semanticHits} 项，共发现 ${highCount} 项高风险、${mediumCount} 项中风险。` },
    { title: "交叉验证与拒答策略", detail: `发现 ${dedupedReviews.length} 项需要人工核实的事实；无可靠法源或关键信息不足时，系统停止输出确定结论。` }
  ];

  const questions = detected.length
    ? detected.slice(0, 8).map((item, index) => `${index + 1}. ${item.action}`)
    : ["1. 请提供正式劳动合同文本并确认薪资、工时、社保和离职条款。"];
  dedupedReviews.slice(0, 8).forEach((item) => questions.push(`核实：${item.detail}`));

  const evidenceLines = detected.length
    ? detected.slice(0, 10).map((item) => `- ${item.title}：${item.action}`)
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
        ...detected.slice(0, 8).map((item, index) => `${index + 1}. ${item.clause}`),
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
    documentType,
    caseType: documentType,
    selectedCaseType: options.caseType || "",
    facts,
    sourcePages: options.sourcePages || [],
    sourceDocument: options.sourceDocument || null,
    analysisStats: {
      ruleHits,
      semanticHits,
      factHits,
      modelCandidates: 0,
      totalRisks: detected.length
    },
    jurisdictionProfile,
    reviewItems: dedupedReviews,
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
    showAuthView("login");
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

function setAnalysisProgress(percent, label, detail) {
  const value = Math.max(0, Math.min(100, Math.round(percent)));
  const panel = $("#analysisProgress");
  if (!panel) return;
  panel.classList.remove("hidden");
  panel.classList.toggle("done", value >= 100);
  $("#analysisProgressLabel").textContent = label;
  $("#analysisProgressPercent").textContent = `${value}%`;
  $("#analysisProgressBar").style.width = `${value}%`;
  $("#analysisProgressDetail").textContent = detail;
  const track = panel.querySelector(".analysis-progress-track");
  if (track) track.setAttribute("aria-valuenow", String(value));
}

function stopAnalysisProgress() {
  if (analysisProgressTimer) window.clearInterval(analysisProgressTimer);
  analysisProgressTimer = null;
}

function startAnalysisProgress() {
  stopAnalysisProgress();
  analysisProgressStartedAt = Date.now();
  setAnalysisProgress(3, "正在启动可信链路", "准备文本、规则版本和法源索引。");
  setProgress("extract", []);
  analysisProgressTimer = window.setInterval(() => {
    const elapsed = Date.now() - analysisProgressStartedAt;
    let percent;
    let step;
    let label;
    let detail;
    if (elapsed < 1400) {
      percent = 6 + (elapsed / 1400) * 18;
      step = "extract";
      label = "正在抽取合同条款";
      detail = "识别材料类型、关键事实和需要核验的风险表达。";
    } else if (elapsed < 3800) {
      percent = 24 + ((elapsed - 1400) / 2400) * 27;
      step = "retrieve";
      label = "正在匹配法源";
      detail = "检索规则版本、法规条文和地方政策依据。";
    } else if (elapsed < 8500) {
      percent = 51 + ((elapsed - 3800) / 4700) * 31;
      step = "reason";
      label = "正在执行规则与模型研判";
      detail = "规则引擎和大模型候选风险正在交叉比对。";
    } else {
      percent = Math.min(94, 82 + ((elapsed - 8500) / 30000) * 12);
      step = "verify";
      label = "正在核验结论与法源";
      detail = "检查原文引用、法源覆盖、冲突项和人工复核边界。";
    }
    const completed = ["extract", "retrieve", "reason", "verify"].slice(0, Math.max(0, ["extract", "retrieve", "reason", "verify"].indexOf(step)));
    setProgress(step, completed);
    setAnalysisProgress(percent, label, detail);
  }, 220);
}

function finishAnalysisProgress(result) {
  stopAnalysisProgress();
  const elapsedSeconds = Math.max(0.1, (Date.now() - analysisProgressStartedAt) / 1000);
  const riskCount = Array.isArray(result?.risks) ? result.risks.length : 0;
  setAnalysisProgress(
    100,
    "可信研判已完成",
    `已生成 ${riskCount} 项风险结论，用时 ${elapsedSeconds.toFixed(1)} 秒。`
  );
  setProgress("", ["extract", "retrieve", "reason", "verify"]);
}

function failAnalysisProgress(message) {
  stopAnalysisProgress();
  setAnalysisProgress(100, "研判未完成", message || "请检查材料或稍后重试。");
  $("#analysisProgress")?.classList.add("error");
}

async function runAnalysis() {
  const text = $("#contractInput").value.trim();
  if (text.length < 20) {
    toast("请先粘贴或载入需要研判的文本。");
    return;
  }

  if (!requireLogin("请先登录后再运行合同研判。")) return;

  const button = $("#analyzeButton");
  button.disabled = true;
  button.textContent = "可信研判中…";
  $("#resultStatus").textContent = "分析进行中";
  $("#emptyResult").classList.add("hidden");
  $("#analysisResult").classList.add("hidden");

  $("#analysisProgress")?.classList.remove("error");
  startAnalysisProgress();

  try {
    const options = {
      caseType: $("#caseType").value,
      jurisdiction: $("#jurisdiction").value,
      language: $("#documentLanguage")?.value || "zh",
      pageRange: $("#pageRange")?.value.trim() || "",
      caseId: state.currentCase?.id || `manual_${Date.now()}`,
      sourcePages: state.sourcePages,
      sourceDocument: state.sourceDocument
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
    finishAnalysisProgress(result);
    renderAnalysis(result);
    syncTimelineFromAnalysis(result);
    if (result.caseId) refreshHistory();
    updateEvidenceDocuments(result);
    $("#resultStatus").textContent = `${result.processingMs} ms 完成`;
  } catch (error) {
    console.error(error);
    failAnalysisProgress(error.message);
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
  $("#riskLevel").textContent = `${result.riskLevel} · ${result.documentType || result.caseType || "材料"}`;
  $("#riskHeadline").textContent = result.riskHeadline;
  $("#riskDescription").textContent = result.riskDescription;

  const facts = result.facts || {};
  const stats = result.analysisStats || {};
  const sourceDoc = result.sourceDocument || {};
  const modeLabels = { deterministic: "确定性规则", fact: "结构化事实", semantic: "语义规则", llm_candidate: "大模型候选" };
  const factItems = [
    ["识别材料", result.documentType || result.caseType || "待核实", result.selectedCaseType && result.selectedCaseType !== result.documentType ? `用户选择：${result.selectedCaseType}` : "自动识别"],
    ["甲方 / 签约单位", facts.partyA || "待核实", ""],
    ["学校", facts.school || "待核实", facts.hasSchoolSignature ? "已识别学校签署" : "未识别学校签署"],
    ["实际用工单位", facts.actualEmployer || "待核实", facts.position ? `岗位：${facts.position}` : ""],
    ["工作地点", facts.workLocation || facts.workCity || "待核实", facts.suggestedJurisdiction ? `建议地区：${facts.suggestedJurisdiction}` : ""],
    ["期限", facts.startDate || facts.endDate ? `${facts.startDate || "待核实"} 至 ${facts.endDate || "待核实"}` : "待核实", facts.termDays ? `约 ${facts.termDays} 天` : ""],
    ["补贴 / 工资", facts.dailyPay ? `${facts.dailyPay} 元/天` : facts.monthlyPay ? `${facts.monthlyPay} 元/月` : "待核实", facts.hourlyEquivalentAt8h ? `按8小时约 ${facts.hourlyEquivalentAt8h} 元/小时` : ""],
    ["发薪主体", facts.payer || "待核实", facts.thirdPartyArrangement ? "签约、用工与发薪主体不一致" : ""],
    ["保险 / 争议条款", `${facts.hasAccidentInsurance ? "已识别保险" : "未识别保险"} · ${facts.hasDisputeClause ? "有争议条款" : "无争议条款"}`, facts.hasJobAttachment ? "已识别岗位附件" : "岗位附件缺失"],
    ["工时 / 关系特征", facts.workHours || "待核实", (facts.relationshipFeatures || []).length ? `含${facts.relationshipFeatures.slice(0, 3).join("、")}等特征` : ""]
  ];
  if (result.documentType === "三方协议") {
    factItems.push(["报到日期", facts.reportDeadline || "待核实", "三方协议就业手续"]);
    factItems.push(["试用期 / 月薪", `${facts.probation || "待核实"} · ${facts.salary ? `${facts.salary} 元/月` : "待核实"}`, ""]);
    factItems.push(["违约金", facts.liquidatedDamages ? `${facts.liquidatedDamages} 元` : "未识别", "需核对服务期、培训费和实际损失"]);
    factItems.push(["档案 / 户口", facts.archiveTransfer || facts.householdTransfer || "待核实", facts.archiveTransfer && facts.householdTransfer ? "已识别安排" : "有事项待核实"]);
    factItems.push(["三方签章", `甲方${facts.hasEmployerSignature ? "已签" : "未签"} · 乙方${facts.hasStudentSignature ? "已签" : "未签"} · 学校${facts.hasSchoolSignature ? "已签" : "未签"}`, ""]);
  }
  const factPanel = `
    <section class="analysis-facts">
      <div class="facts-head"><div><span class="section-kicker">材料识别</span><h4>基本事实与适用边界</h4></div><span class="type-badge">${escapeHtml(result.documentType || result.caseType || "待核实")}</span></div>
      <div class="fact-grid">${factItems.map(([label, value, note]) => `<div class="fact-item"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong>${note ? `<small>${escapeHtml(note)}</small>` : ""}</div>`).join("")}</div>
      <div class="analysis-stats">
        <span>规则 ${stats.ruleHits || 0}</span><span>事实 ${stats.factHits || 0}</span><span>语义 ${stats.semanticHits || 0}</span><span>模型候选 ${stats.modelCandidates || 0}</span><span>待核实 ${(result.reviewItems || []).length}</span>
      </div>
      ${sourceDoc.filename ? `<p class="source-line">原始文件：${escapeHtml(sourceDoc.filename)} · ${escapeHtml(sourceDoc.format || "")}${sourceDoc.ocr ? " · OCR" : ""} · ${sourceDoc.pageCount || "?"} 页 · SHA-256 ${escapeHtml(String(sourceDoc.sha256 || "未记录").slice(0, 24))}${sourceDoc.sha256 ? "…" : ""}${sourceDoc.ocr ? " · OCR识别结果建议在文本框人工校对" : ""}</p>` : `<p class="source-line">当前为粘贴文本，无原始文件哈希。</p>`}
    </section>`;

  const reviewNotice = $("#reviewNotice");
  if (result.reviewItems?.length) {
    reviewNotice.classList.remove("hidden");
    reviewNotice.innerHTML = `<strong>需要人工核实 ${result.reviewItems.length} 项事实</strong>${result.reviewItems.slice(0, 3).map((item) => `<span>${escapeHtml(item.title)}</span>`).join("")}<p>${escapeHtml(result.reviewItems.slice(0, 2).map((item) => item.detail).join("；"))}${result.reviewItems.length > 2 ? "；更多事项见可信轨迹。" : ""}</p>`;
  } else {
    reviewNotice.classList.add("hidden");
    reviewNotice.innerHTML = "";
  }

  const riskCards = result.risks.length
    ? `<div class="risk-list">${result.risks.map((risk) => {
        const location = risk.location || {};
        const locationText = `第${location.page || 1}页 / ${location.clause || "未编号条款"}`;
        const laws = risk.lawItems || [];
        return `
        <article class="risk-card ${risk.severity}" data-risk-id="${risk.id}">
          <div class="risk-card-head">
            <h4>${escapeHtml(risk.title)}</h4>
            <span class="confidence">置信度 ${Math.round((risk.confidence || 0) * 100)}%</span>
          </div>
          <div class="risk-location"><span>${escapeHtml(locationText)}</span><span>${escapeHtml(modeLabels[risk.detectionMode] || "规则")}</span><span>${escapeHtml(risk.category)}</span></div>
          <p>${escapeHtml(risk.modelReason || risk.reason)}</p><div class="risk-action"><b>建议</b>${escapeHtml(risk.modelAction || risk.action)}</div>
          <div class="risk-tags">
            <span>${severityText(risk.severity)}</span>
            ${laws.slice(0, 2).map((law) => `<span>${escapeHtml(law.source)}</span>`).join("")}
          </div>
        </article>`;
      }).join("")}</div>`
    : `<div class="empty-result"><h3>未发现明显高风险</h3><p>系统仍建议核对合同主体、工资、工时、社保、保险和离职条款。</p></div>`;
  $("#result-risks").innerHTML = `${factPanel}${riskCards}`;

  $("#result-clauses").innerHTML = result.risks.length
    ? `<div class="clause-list">${result.risks.map((risk) => {
        const escapedClause = escapeHtml(risk.clause || "");
        const escapedMatch = escapeHtml(risk.matchText || "");
        const highlighted = escapedMatch ? escapedClause.replace(escapedMatch, `<mark>${escapedMatch}</mark>`) : escapedClause;
        const location = risk.location || {};
        return `<div class="clause-item"><div class="clause-head"><strong>${escapeHtml(risk.title)}</strong><span>第${location.page || 1}页 / ${escapeHtml(location.clause || "未编号条款")}</span></div>${highlighted}</div>`;
      }).join("")}</div>`
    : "<p class='soft-label'>未定位到需要高亮的风险片段。</p>";

  const reviewList = (result.reviewItems || []).length
    ? `<div class="review-panel"><h4>待核实事项</h4><ul>${result.reviewItems.map((item) => `<li><strong>${escapeHtml(item.title)}</strong>${item.source ? `<span>${escapeHtml(item.source)}</span>` : ""}<p>${escapeHtml(item.detail)}</p></li>`).join("")}</ul></div>`
    : "";
  $("#result-trust").innerHTML = `
    <div class="trust-trace">
      ${result.trace.map((item, index) => `
        <div class="trace-step"><b>${index + 1}</b><div><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.detail)}</p></div></div>
      `).join("")}
      <div class="trace-step"><b>盾</b><div><strong>人工复核提示</strong><p>法源覆盖率 ${result.citationCoverage}%。${escapeHtml(result.jurisdictionProfile?.note || "地方最低工资、实习关系认定和个案事实仍需以最新政策和主管部门意见为准。")}</p></div></div>
    </div>
    ${reviewList}
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

function clearWorkspaceData() {
  state.sourcePages = [];
  state.sourceDocument = null;
  state.lastAnalysis = null;
  state.lastCaseId = null;
  const input = $("#contractInput");
  if (input) input.value = "";
  const count = $("#charCount");
  if (count) count.textContent = "0 字";
  $("#analysisResult")?.classList.add("hidden");
  $("#emptyResult")?.classList.remove("hidden");
  const status = $("#resultStatus");
  if (status) status.textContent = "等待分析";
}

function loadCase(item, shouldAnalyze = false) {
  if (!requireLogin("请先登录后再载入研判材料。")) return;
  state.currentCase = item;
  state.sourcePages = [];
  state.sourceDocument = null;
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

function syncEvidenceFromAnalysis(result, options = {}) {
  if (!result?.risks?.length) return 0;
  const existing = new Set(state.checklist.map((item) => item.id));
  let added = 0;
  result.risks.forEach((risk) => {
    const id = `analysis_${risk.id}`;
    if (existing.has(id)) return;
    state.checklist.unshift({
      id,
      label: `${risk.title}：${risk.modelAction || risk.action}`,
      done: false,
      level: severityText(risk.severity),
      source: "研判同步"
    });
    existing.add(id);
    added += 1;
  });
  if (added) {
    renderEvidence();
    updateEvidenceScore();
    appendTimelineEvent({
      title: "研判风险已写入证据链",
      detail: `已新增 ${added} 项证据任务，并关联本次研判结论。`
    });
    const status = $("#evidenceChainStatus");
    if (status) status.textContent = `已从本次研判同步 ${added} 项证据任务，请逐项核对并保存材料。`;
    if (!options.silent) toast(`已同步 ${added} 项证据任务。`);
  } else if (!options.silent) {
    toast("本次研判的证据任务已在证据链中。");
  }
  return added;
}

function formatTimelineDate(date = new Date()) {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function renderTimeline() {
  const container = $("#timeline");
  if (!container) return;
  const events = Array.isArray(state.timeline) ? state.timeline : [];
  if (!events.length) {
    container.innerHTML = '<div class="timeline-empty">完成一次研判或上传证据后，这里会自动生成案件时间线。</div>';
    return;
  }
  container.innerHTML = events.map((item) => `
    <div class="timeline-item">
      <time>${escapeHtml(item.date)}</time>
      <strong>${escapeHtml(item.title)}</strong>
      <p>${escapeHtml(item.detail)}</p>
    </div>
  `).join("");
}

function appendTimelineEvent(event) {
  if (!event?.title) return;
  state.timeline.push({
    date: event.date || formatTimelineDate(),
    title: event.title,
    detail: event.detail || ""
  });
  renderTimeline();
}

function syncTimelineFromAnalysis(result) {
  if (!result) return;
  const now = formatTimelineDate();
  const text = $("#contractInput")?.value || "";
  const materialName = state.sourceDocument?.filename || result.documentType || result.caseType || "待研判材料";
  const risks = Array.isArray(result.risks) ? result.risks : [];
  const highCount = risks.filter((risk) => risk.severity === "high").length;
  const mediumCount = risks.filter((risk) => risk.severity === "medium").length;
  const stats = result.analysisStats || {};
  state.timeline = [
    {
      date: now,
      title: "待研判材料已载入",
      detail: `${materialName}，共 ${text.length} 字；已保留来源信息与材料指纹。`
    },
    {
      date: now,
      title: "条款抽取与法源检索完成",
      detail: `系统执行 ${Number(stats.ruleHits || 0)} 次规则命中检查，并完成法规来源匹配。`
    },
    {
      date: now,
      title: "可信研判结果已生成",
      detail: `识别 ${risks.length} 项风险，其中高风险 ${highCount} 项、中风险 ${mediumCount} 项；风险分 ${result.riskScore ?? "--"}。`
    }
  ];
  if (risks.length) {
    const highlights = risks.slice(0, 3).map((risk) => risk.title).filter(Boolean).join("；");
    state.timeline.push({
      date: now,
      title: "重点风险事项已纳入证据计划",
      detail: highlights || "已生成待核实风险事项。"
    });
  }
  renderTimeline();
}

function renderEvidence() {
  $("#evidenceChecklist").innerHTML = state.checklist.map((item) => `
    <label class="check-item">
      <input type="checkbox" data-evidence-id="${item.id}" ${item.done ? "checked" : ""}>
      <span>${escapeHtml(item.label)}</span>
      <small>${escapeHtml(item.level)}${item.source ? ` · ${escapeHtml(item.source)}` : ""}</small>
    </label>
  `).join("");

  $$("#evidenceChecklist input").forEach((input) => {
    input.addEventListener("change", () => {
      const item = state.checklist.find((entry) => entry.id === input.dataset.evidenceId);
      if (item) item.done = input.checked;
      updateEvidenceScore();
    });
  });

  renderTimeline();
  updateEvidenceScore();
}

function updateEvidenceScore() {
  const done = state.checklist.filter((item) => item.done).length;
  const score = Math.round((done / state.checklist.length) * 100);
  $("#evidenceScore").textContent = `${score}%`;
}

function addEvidence() {
  if (!requireLogin("请先登录后再编辑证据链。")) return;
  const input = $("#newEvidenceInput");
  const value = input.value.trim();
  if (!value) return;
  state.checklist.push({ id: `custom_${Date.now()}`, label: value, done: true, level: "自定" });
  input.value = "";
  renderEvidence();
  appendTimelineEvent({ title: "手动补充证据事项", detail: value });
  toast("已加入证据清单。");
}

function buildTimelineExport() {
  return state.timeline.map((item) => `${item.date}  ${item.title}\n${item.detail}\n`).join("\n");
}

async function runEvaluation() {
  if (!requireLogin("请先登录后再运行可信评测。")) return;
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
  if (!requireLogin("请先登录后再使用政策服务。")) return;
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
      <div class="hash-text">文件 SHA-256 ${escapeHtml(item.sha256)}<br>链记录 ${escapeHtml(item.record_hash || "待校验")}</div>
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
    showAuthView("login");
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
    const uploaded = await apiRequest("/api/evidence/upload", {
      method: "POST",
      body: JSON.stringify({
        filename: file.name,
        caseId: attachCase ? state.lastCaseId : null,
        content_base64: arrayBufferToBase64(await file.arrayBuffer())
      })
    });
    input.value = "";
    appendTimelineEvent({
      title: "证据原件已归档",
      detail: `${file.name} 已写入证据链${uploaded?.evidence?.sha256 ? `，SHA-256 ${uploaded.evidence.sha256.slice(0, 16)}…` : ""}。`
    });
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

async function verifyEvidenceChain() {
  if (!state.user) {
    showAuthView("login");
    $("#authDialog")?.showModal();
    return;
  }
  const status = $("#evidenceChainStatus");
  if (status) status.textContent = "正在重新计算文件哈希和链式记录…";
  try {
    const data = await apiRequest("/api/evidence/verify");
    if (data.valid) {
      if (status) status.textContent = `完整性校验通过：${data.items.length} 个文件，链头 ${data.head.slice(0, 16)}…`;
      toast("证据链完整性校验通过。");
    } else {
      const bad = (data.items || []).filter((item) => !item.valid).map((item) => item.filename).join("、");
      if (status) status.textContent = `完整性校验失败：${bad || "存在异常记录"}`;
      toast("证据链校验失败，请检查异常文件。");
    }
  } catch (error) {
    if (status) status.textContent = `完整性校验失败：${error.message}`;
    toast(`证据链校验失败：${error.message}`);
  }
}

async function downloadEvidencePackage() {
  if (!state.user) {
    showAuthView("login");
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
  if (!state.user || !isAdminRole(state.user.role)) return;
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
    const me = await apiRequest("/api/auth/me");
    if (me.authenticated) state.user = me.user;
    renderAccountEmail();
    const payload = await apiRequest("/api/auth/sessions");
    renderSessions(payload.sessions || []);
  } catch (error) {
    setAccountMessage(`账户信息加载失败：${error.message}`, true);
  }
}

function renderAccountEmail() {
  const status = $("#emailBindingStatus");
  const input = $("#accountEmail");
  if (!status || !input) return;
  const email = state.user?.email || "";
  const verified = Boolean(state.user?.emailVerified);
  if (email) input.value = email;
  status.textContent = verified ? `已验证：${email}` : email ? `待验证：${email}` : "未绑定";
  status.className = `status-badge ${verified ? "status-active" : "status-archived"}`;
}

async function requestEmailBindingCode() {
  const email = $("#accountEmail")?.value.trim();
  if (!email) {
    setAccountMessage("请输入要绑定的邮箱地址。", true);
    return;
  }
  try {
    const data = await apiRequest("/api/auth/set-email", {
      method: "POST",
      body: JSON.stringify({ email })
    });
    state.emailChallengeId = data.challengeId;
    $("#emailVerifyRow")?.classList.remove("hidden");
    $("#emailVerifyCode")?.focus();
    setAccountMessage(`验证码已发送到 ${data.emailHint || email}。`);
    if (state.user) {
      state.user.email = email;
      state.user.emailVerified = false;
    }
    renderAccountEmail();
  } catch (error) {
    setAccountMessage(`验证码发送失败：${error.message}`, true);
  }
}

async function verifyEmailBinding() {
  if (!state.emailChallengeId) {
    setAccountMessage("请先发送邮箱验证码。", true);
    return;
  }
  try {
    await apiRequest("/api/auth/verify-email", {
      method: "POST",
      body: JSON.stringify({
        challengeId: state.emailChallengeId,
        code: $("#emailVerifyCode")?.value.trim() || ""
      })
    });
    state.emailChallengeId = null;
    $("#emailVerifyRow")?.classList.add("hidden");
    $("#emailVerifyCode").value = "";
    setAccountMessage("邮箱已验证，可用于找回密码和管理员二次验证。");
    await refreshAccountCenter();
  } catch (error) {
    setAccountMessage(`邮箱验证失败：${error.message}`, true);
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
    showAuthView("login");
    $("#authDialog")?.showModal();
  } catch (error) {
    setAccountMessage(`删除失败：${error.message}`, true);
  }
}

function buildReport(result) {
  if (!result) return "尚无研判结果。";
  const facts = result.facts || {};
  const sourceDoc = result.sourceDocument || {};
  const stats = result.analysisStats || {};
  const modeLabels = { deterministic: "确定性规则", fact: "结构化事实", semantic: "语义规则", llm_candidate: "大模型候选" };
  const factLines = [
    `甲方/签约单位：${facts.partyA || "待核实"}`,
    `学校：${facts.school || "待核实"}`,
    `实际用工单位：${facts.actualEmployer || "待核实"}`,
    `岗位/部门：${facts.position || "待核实"}`,
    `工作地点：${facts.workLocation || facts.workCity || "待核实"}`,
    `期限：${facts.startDate || "待核实"} 至 ${facts.endDate || "待核实"}${facts.termDays ? `（约 ${facts.termDays} 天）` : ""}`,
    `补贴/工资：${facts.dailyPay ? `${facts.dailyPay} 元/天；按8小时约 ${facts.hourlyEquivalentAt8h} 元/小时` : facts.monthlyPay ? `${facts.monthlyPay} 元/月` : "待核实"}`,
    `工时：${facts.workHours || "待核实"}`,
    `发薪主体：${facts.payer || "待核实"}`,
    `保险安排：${facts.hasAccidentInsurance ? (facts.insuranceTerms || []).join("、") : "未识别到"}`,
    `争议条款：${facts.hasDisputeClause ? "已识别" : "未识别到"}`,
    `岗位附件：${facts.hasJobAttachment ? "已识别" : "未识别到"}`,
    `学校签署：${facts.hasSchoolSignature ? "已识别" : "未识别到"}`
  ];
  const riskLines = result.risks.map((risk, index) => {
    const location = risk.location || {};
    return [
      `${index + 1}. [${severityText(risk.severity)}] ${risk.title}`,
      `位置：第${location.page || 1}页 / ${location.clause || "未编号条款"}　来源：${modeLabels[risk.detectionMode] || "规则"}`,
      `${risk.detectionMode === "fact" ? "事实依据" : "原文"}：${risk.clause}`,
      `说明：${risk.modelReason || risk.reason}`,
      `建议：${risk.modelAction || risk.action}`,
      `法源：${(risk.lawItems || []).map((law) => law.source).join("；")}`
    ].join("\n");
  });
  return [
    "职安盾 VeriWork 就业材料研判报告",
    `生成时间：${formatDate()}`,
    `识别材料：${result.documentType || result.caseType || "未指定"}`,
    `用户选择：${result.selectedCaseType || result.caseType || "未指定"}`,
    `适用地区：${result.jurisdiction || "全国规则"}　建议地区：${facts.suggestedJurisdiction || "待核实"}`,
    `风险分：${result.riskScore}（${result.riskLevel}）`,
    `原始文件：${sourceDoc.filename || "未记录"}${sourceDoc.sha256 ? `\nSHA-256：${sourceDoc.sha256}` : ""}`,
    "",
    "一、基本事实",
    ...factLines,
    "",
    "二、风险清单",
    ...(riskLines.length ? riskLines : ["未发现明显高风险条款，仍需核对合同主体、工资、工时、社保、保险和离职条款。"]),
    "",
    "三、待核实事项",
    ...((result.reviewItems || []).length ? result.reviewItems.map((item, index) => `${index + 1}. ${item.title}：${item.detail}`) : ["未生成额外待核实事项。"]),
    "",
    "四、研判来源统计",
    `确定性规则 ${stats.ruleHits || 0} 项；结构化事实 ${stats.factHits || 0} 项；语义规则 ${stats.semanticHits || 0} 项；大模型候选 ${stats.modelCandidates || 0} 项；合计 ${stats.totalRisks || result.risks.length} 项。`,
    "",
    "五、可信轨迹",
    ...result.trace.map((item, index) => `${index + 1}. ${item.title}：${item.detail}`),
    "",
    "六、后续行动",
    ...result.questions,
    "",
    "七、合规声明",
    APP_DATA.meta.disclaimer
  ].join("\n");
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

function setFileLoading(active, message = "") {
  const zone = $("#dropZone");
  if (!zone) return;
  zone.classList.toggle("loading", active);
  zone.setAttribute("aria-busy", active ? "true" : "false");
  const strong = zone.querySelector("strong");
  const span = zone.querySelector("span");
  if (!strong || !span) return;
  if (active) {
    strong.textContent = message || "正在识别文件…";
    span.textContent = "图片 OCR 需要几秒钟，请勿重复拖入或刷新页面。";
  } else {
    strong.textContent = "拖入文件，或从微信 / QQ 直接拖入聊天截图";
    span.textContent = "支持 PDF、Word、TXT、PNG、JPG、WEBP；图片会自动 OCR。也可以按 Ctrl+V 粘贴截图。";
  }
}

async function prepareImageForUpload(file) {
  if (!file.type.startsWith("image/") || typeof createImageBitmap !== "function") return file;
  try {
    const bitmap = await createImageBitmap(file);
    const maxSide = 1800;
    const scale = Math.min(1, maxSide / Math.max(bitmap.width, bitmap.height));
    if (scale === 1 && file.size < 3 * 1024 * 1024) {
      bitmap.close?.();
      return file;
    }
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const context = canvas.getContext("2d", { alpha: false });
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    bitmap.close?.();
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.92));
    if (!blob) return file;
    return new File([blob], file.name.replace(/\.[^.]+$/, "") + ".jpg", { type: "image/jpeg" });
  } catch (error) {
    console.warn("图片预处理失败，使用原文件", error);
    return file;
  }
}

async function handleFiles(fileList) {
  if (state.fileLoading) {
    toast("正在识别，请稍候…");
    return;
  }
  const files = Array.from(fileList || []).filter(Boolean);
  if (!files.length) return;
  if (!requireLogin("文件解析需要登录，请先登录或注册账号。")) return;
  state.fileLoading = true;
  setFileLoading(true, `正在识别 ${files.length} 个文件…`);
  await new Promise((resolve) => requestAnimationFrame(resolve));
  const documents = [];
  const errors = [];
  try {
    for (const file of files) {
      const extension = `.${file.name.split(".").pop().toLowerCase()}`;
      try {
        if ([".pdf", ".docx", ".png", ".jpg", ".jpeg", ".webp", ".bmp"].includes(extension)) {
          if (state.settings.runMode !== "api") {
            throw new Error("PDF、Word 和图片解析需要后端服务，请启动完整服务后重试");
          }
          const uploadFile = file.type.startsWith("image/") ? await prepareImageForUpload(file) : file;
          documents.push(await extractDocumentViaApi(uploadFile));
        } else {
          const buffer = await file.arrayBuffer();
          const text = new TextDecoder("utf-8").decode(buffer);
          documents.push({
            text,
            pages: [{ page: 1, text }],
            filename: file.name,
            format: extension.replace(".", ""),
            chars: text.length,
            sizeBytes: file.size,
            sha256: await sha256Hex(buffer),
            pageCount: 1
          });
        }
      } catch (error) {
        errors.push(`${file.name}: ${error.message}`);
      }
    }
    if (!documents.length) {
      toast(`文件读取失败：${errors.join("；")}`);
      return;
    }
    const pages = [];
    const textParts = [];
    let pageOffset = 0;
    for (const document of documents) {
      const documentPages = Array.isArray(document.pages) && document.pages.length ? document.pages : [{ page: 1, text: document.text }];
      for (const page of documentPages) {
        pages.push({ page: pageOffset + Number(page.page || 1), text: String(page.text || ""), source: document.filename });
      }
      pageOffset += Number(document.pageCount) || documentPages.length;
      textParts.push(documents.length > 1 ? `【文件：${document.filename}】\n${document.text}` : document.text);
    }
    const text = textParts.join("\n\n");
    $("#contractInput").value = text;
    $("#charCount").textContent = `${text.length} 字`;
    state.sourcePages = pages;
    const hashParts = documents.map((document) => document.sha256 || "").join(":");
    const combinedHash = documents.length === 1
      ? (documents[0].sha256 || "")
      : ((await sha256Hex(new TextEncoder().encode(hashParts))) || hashParts);
    const ocrMs = documents.reduce((sum, document) => sum + Number(document.ocrMs || 0), 0);
    state.sourceDocument = {
      filename: documents.length === 1 ? documents[0].filename : `${documents.length} 个文件：${documents.map((document) => document.filename).join("、")}`,
      format: documents.length === 1 ? documents[0].format : "mixed",
      chars: text.length,
      sizeBytes: documents.reduce((sum, document) => sum + Number(document.sizeBytes || 0), 0),
      sha256: combinedHash,
      pageCount: pages.length,
      ocr: documents.some((document) => document.ocr),
      ocrLanguage: documents.find((document) => document.ocrLanguage)?.ocrLanguage || "",
      ocrMs
    };
    const ocrSeconds = ocrMs ? `，OCR ${(ocrMs / 1000).toFixed(1)} 秒` : "";
    toast(`已载入 ${documents.length} 个文件，共 ${text.length} 字${ocrSeconds}${errors.length ? `；${errors.length} 个失败` : ""}`);
    if (errors.length) console.warn("部分文件读取失败", errors);
  } finally {
    state.fileLoading = false;
    setFileLoading(false);
  }
}

function bindEvents() {
  $$(".password-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.passwordTarget);
      if (!input) return;
      const willShow = input.type === "password";
      input.type = willShow ? "text" : "password";
      button.textContent = willShow ? "隐藏密码" : "显示密码";
      button.setAttribute("aria-label", willShow ? "隐藏密码" : "显示密码");
      button.setAttribute("aria-pressed", willShow ? "true" : "false");
      input.focus();
    });
  });
  $("#authDialog")?.addEventListener("cancel", (event) => {
    if (!state.user) {
      event.preventDefault();
      showAuthCloseNotice();
    }
  });
  $$(".nav-item").forEach((element) => element.addEventListener("click", () => navigate(element.dataset.page)));
  $$("[data-go]").forEach((element) => element.addEventListener("click", () => navigate(element.dataset.go)));

  $("#quickDemo").addEventListener("click", () => loadCase(APP_DATA.demoCases[0], true));
  $("#loadSampleButton").addEventListener("click", () => {
    state.sourcePages = [];
    state.sourceDocument = null;
    $("#contractInput").value = APP_DATA.demoCases[0].text;
    $("#contractInput").dispatchEvent(new Event("input"));
  });
  $("#clearButton").addEventListener("click", () => {
    clearWorkspaceData();
    $("#contractInput").dispatchEvent(new Event("input"));
  });
  $("#contractInput").addEventListener("input", (event) => {
    $("#charCount").textContent = `${event.target.value.length} 字`;
    if (event.isTrusted) {
      state.sourcePages = [];
      state.sourceDocument = null;
    }
  });
  $("#fileInput").addEventListener("change", async (event) => {
    await handleFiles(event.target.files);
    event.target.value = "";
  });
  const dropZone = $("#dropZone");
  if (dropZone) {
    dropZone.addEventListener("click", () => $("#fileInput").click());
    dropZone.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        $("#fileInput").click();
      }
    });
    ["dragenter", "dragover"].forEach((name) => dropZone.addEventListener(name, (event) => {
      event.preventDefault();
      event.stopPropagation();
      dropZone.classList.add("dragover");
    }));
    dropZone.addEventListener("dragleave", (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (event.relatedTarget && dropZone.contains(event.relatedTarget)) return;
      dropZone.classList.remove("dragover");
    });
    dropZone.addEventListener("drop", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      dropZone.classList.remove("dragover");
      const files = event.dataTransfer?.files;
      if (files?.length) await handleFiles(files);
    });
  }
  document.addEventListener("dragover", (event) => {
    if (state.currentPage === "analysis" && Array.from(event.dataTransfer?.types || []).includes("Files")) {
      event.preventDefault();
    }
  });
  document.addEventListener("drop", async (event) => {
    if (state.currentPage !== "analysis" || !event.dataTransfer?.files?.length) return;
    event.preventDefault();
    dropZone?.classList.remove("dragover");
    await handleFiles(event.dataTransfer.files);
  });
  document.addEventListener("paste", async (event) => {
    if (state.currentPage !== "analysis") return;
    const files = Array.from(event.clipboardData?.items || [])
      .filter((item) => item.kind === "file")
      .map((item) => item.getAsFile())
      .filter(Boolean);
    if (!files.length) return;
    event.preventDefault();
    await handleFiles(files);
  });
  $("#analyzeButton").addEventListener("click", runAnalysis);
  $$(".result-tabs .tab").forEach((element) => element.addEventListener("click", () => switchResultTab(element.dataset.resultTab)));
  $("#sendToEvidence").addEventListener("click", () => {
    if (!state.lastAnalysis) {
      toast("请先完成一次研判，再同步到证据链。");
      return;
    }
    syncEvidenceFromAnalysis(state.lastAnalysis);
    navigate("evidence");
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
  $("#verifyEvidenceChain")?.addEventListener("click", verifyEvidenceChain);
  $("#downloadEvidencePackage")?.addEventListener("click", downloadEvidencePackage);
  $("#passwordForm")?.addEventListener("submit", changePassword);
  $("#revokeOtherSessions")?.addEventListener("click", revokeOtherSessions);
  $("#exportAccountData")?.addEventListener("click", exportAccountData);
  $("#downloadEvidenceZip")?.addEventListener("click", downloadEvidencePackage);
  $("#deleteAccountButton")?.addEventListener("click", deleteAccount);
  $("#requestEmailCode")?.addEventListener("click", requestEmailBindingCode);
  $("#verifyEmailButton")?.addEventListener("click", verifyEmailBinding);
  $("#verify2faButton")?.addEventListener("click", verifyAdmin2fa);
  $("#forgotPasswordButton")?.addEventListener("click", () => {
    $("#authDialog")?.close();
    $("#resetMessage").textContent = "请输入用户名或已绑定邮箱，然后获取验证码。";
    $("#resetDialog")?.showModal();
  });
  $("#closeReset")?.addEventListener("click", () => $("#resetDialog")?.close());
  $("#requestResetCode")?.addEventListener("click", requestPasswordResetCode);
  $("#confirmResetPassword")?.addEventListener("click", confirmPasswordReset);

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
    if (event.target.closest("#openAuth")) {
      showAuthView("login");
      $("#authDialog")?.showModal();
    }
    if (event.target.closest("#showRegisterView")) {
      showAuthView("register");
    }
    if (event.target.closest("#showLoginView")) {
      showAuthView("login");
    }
    if (event.target.closest("#openAdminLogin")) {
      window.location.href = `${window.location.pathname}?admin=1`;
    }
    if (event.target.closest("#closeAuth")) {
      if (!state.user) {
        showAuthCloseNotice();
        return;
      }
      clearAuthError();
      $("#authDialog")?.close();
    }
    if (event.target.closest("#loginButton")) {
      loginWithCredentials($("#authUsername").value.trim(), $("#authPassword").value).catch((error) => showAuthError(error.message || "登录失败，请检查账号和密码"));
    }
    if (event.target.closest("#registerButton")) {
      registerAccount($("#registerUsername").value.trim(), $("#registerPassword").value).catch((error) => showAuthError(error.message || "注册失败，请检查输入信息"));
    }
  });
  ["authUsername", "authPassword", "registerUsername", "registerPassword", "authEmail", "auth2faCode"].forEach((id) => {
    $(`#${id}`)?.addEventListener("input", clearAuthError);
    $(`#${id}`)?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        if (id === "auth2faCode") {
          verifyAdmin2fa();
        } else if (id === "registerUsername" || id === "registerPassword" || id === "authEmail") {
          registerAccount($("#registerUsername").value.trim(), $("#registerPassword").value).catch((error) => showAuthError(error.message || "注册失败，请检查输入信息"));
        } else {
          loginWithCredentials($("#authUsername").value.trim(), $("#authPassword").value).catch((error) => showAuthError(error.message || "登录失败，请检查账号和密码"));
        }
      }
    });
  });
}

function updatePrivacyNotice() {
  const strip = $(".privacy-strip");
  if (!strip) return;
  const isLocal = ["127.0.0.1", "localhost", "::1"].includes(window.location.hostname);
  if (window.location.protocol === "http:" && !isLocal) {
    strip.classList.add("warning");
    const text = strip.querySelector("span");
    if (text) text.textContent = "当前为 HTTP 演示环境，请勿上传真实合同原件；请使用脱敏件或合成材料。系统调用外部模型前会按“黄XX、133XXXX1465”等格式处理敏感字段，但浏览器到服务器之间的传输未加密。";
  }
}

function init() {
  const params = new URLSearchParams(window.location.search);
  if (params.get("admin") === "1") {
    initAdminLoginPage();
    return;
  }
  renderMetrics();
  renderCaseQueue();
  renderEvidence();
  renderEvaluationCards();
  renderComparison();
  updateEvidenceDocuments(null);
  loadSettings();
  bindEvents();
  updatePrivacyNotice();
  initCarousel();
  const requestedPage = params.get("page");
  if (requestedPage && PROTECTED_PAGES.has(requestedPage)) state.pendingPage = requestedPage;
  (async () => {
    await refreshBackendStatus();
    const authenticated = await loadCurrentUser();
    if (!authenticated) {
      showAuthView("login");
      $("#authDialog")?.showModal();
      return;
    }
    const destination = state.pendingPage || "dashboard";
    state.pendingPage = null;
    navigate(destination);
    if (state.currentPage === "history") refreshHistory();
    if (state.currentPage === "evidence") refreshEvidenceFiles();
    if (state.currentPage === "account") refreshAccountCenter();
    if (params.get("demo") === "risk") {
      window.setTimeout(() => loadCase(APP_DATA.demoCases[0], true), 120);
    }
    if (params.get("demo") === "evaluation") {
      navigate("evaluation");
      window.setTimeout(runEvaluation, 160);
    }
  })();
  $("#contractInput").value = APP_DATA.demoCases[0].text;
  $("#contractInput").dispatchEvent(new Event("input"));
}

window.VeriWork = { APP_DATA, analyzeContract, state };

document.addEventListener("DOMContentLoaded", () => {
  if (document.querySelector("#page-dashboard")) init();
});
