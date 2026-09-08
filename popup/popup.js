// popup.js
const checksEl = document.getElementById("checks");
const loadingEl = document.getElementById("loading-text");
const scoreNumEl = document.getElementById("score-num");
const scoreLabelEl = document.getElementById("score-label");
const scoreDomainEl = document.getElementById("score-domain");
const scoreDotEl = document.getElementById("score-dot");
const rescanBtn = document.getElementById("rescan-btn");

const SENSITIVE_PERMISSIONS = ["geolocation", "camera", "microphone", "clipboard-read"];

function sendMessage(message) {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function scanVulnerableLibs(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      files: ["lib/vulnerable-libs.js"],
    });
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      func: () => window.__secInspectorScanVulnerableLibs(),
    });
    return result || [];
  } catch (e) {
    return [];
  }
}

async function scanDom(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["lib/dom-scan.js"],
    });
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => window.__secInspectorScanDom(),
    });
    return result;
  } catch (e) {
    return null;
  }
}

function gradeHeaders(headerData, isHttps) {
  const h = headerData?.headers || {};
  const items = [];

  items.push({
    id: "csp",
    title: "Content-Security-Policy",
    status: h["content-security-policy"] ? "safe" : "warn",
    summary: h["content-security-policy"]
      ? "Present — restricts what the page can load and execute."
      : "Missing — the page has no policy limiting script/resource sources.",
  });

  items.push({
    id: "xcto",
    title: "X-Content-Type-Options",
    status: h["x-content-type-options"] === "nosniff" ? "safe" : "warn",
    summary:
      h["x-content-type-options"] === "nosniff"
        ? "Set to nosniff — browsers won't MIME-sniff responses."
        : "Missing — browsers may guess content types, enabling some attacks.",
  });

  const hasFrameProtection =
    !!h["x-frame-options"] || /frame-ancestors/i.test(h["content-security-policy"] || "");
  items.push({
    id: "xfo",
    title: "Clickjacking protection",
    status: hasFrameProtection ? "safe" : "warn",
    summary: hasFrameProtection
      ? "X-Frame-Options or frame-ancestors is set."
      : "No X-Frame-Options or frame-ancestors — page could be framed by others.",
  });

  if (isHttps) {
    items.push({
      id: "hsts",
      title: "Strict-Transport-Security",
      status: h["strict-transport-security"] ? "safe" : "warn",
      summary: h["strict-transport-security"]
        ? "HSTS is set — browsers will enforce HTTPS on repeat visits."
        : "Missing — first visits over HTTP won't be auto-upgraded.",
    });
  }

  items.push({
    id: "refpol",
    title: "Referrer-Policy",
    status: h["referrer-policy"] ? "safe" : "warn",
    summary: h["referrer-policy"]
      ? `Set to "${h["referrer-policy"]}".`
      : "Missing — full URLs may leak to third parties via the Referer header.",
  });

  return items;
}

function gradeCookies(cookies, isHttps) {
  if (!cookies || cookies.length === 0) {
    return {
      id: "cookies",
      title: "Cookies",
      status: "neutral",
      summary: "No cookies set for this domain.",
      detail: [],
    };
  }
  const insecure = cookies.filter((c) => isHttps && !c.secure);
  const noSameSite = cookies.filter((c) => !c.sameSite || c.sameSite === "no_restriction");
  const status = insecure.length > 0 ? "danger" : noSameSite.length > 0 ? "warn" : "safe";
  const summary =
    insecure.length > 0
      ? `${insecure.length} of ${cookies.length} cookie(s) missing the Secure flag on HTTPS.`
      : noSameSite.length > 0
      ? `${noSameSite.length} cookie(s) without a strict SameSite policy.`
      : `${cookies.length} cookie(s), all with reasonable flags.`;
  return {
    id: "cookies",
    title: "Cookies",
    status,
    summary,
    detail: cookies.map(
      (c) => `${c.name} — secure: ${c.secure}, httpOnly: ${c.httpOnly}, sameSite: ${c.sameSite}`
    ),
  };
}

function gradePermissions(permissions) {
  if (!permissions) {
    return {
      id: "permissions",
      title: "Site permissions",
      status: "neutral",
      summary: "Could not read permission state on this page.",
      detail: [],
    };
  }
  const granted = Object.entries(permissions).filter(([, v]) => v === "granted");
  const sensitiveGranted = granted.filter(([name]) => SENSITIVE_PERMISSIONS.includes(name));
  const status = sensitiveGranted.length > 0 ? "warn" : "safe";
  const summary =
    granted.length > 0
      ? `Already granted: ${granted.map(([n]) => n).join(", ")}.`
      : "No device permissions currently granted to this site.";
  return {
    id: "permissions",
    title: "Site permissions",
    status,
    summary,
    isPermissions: true,
    permissions,
  };
}

function gradeMixedContent(dom) {
  const count = dom?.mixedContent?.length || 0;
  return {
    id: "mixed",
    title: "Mixed content",
    status: count > 0 ? "danger" : "safe",
    summary:
      count > 0
        ? `${count} resource(s) loaded over HTTP on an HTTPS page.`
        : "No insecure resources detected on this HTTPS page.",
    detail: (dom?.mixedContent || []).map((m) => `<${m.tag}> ${m.url}`),
  };
}

function gradeForms(dom) {
  const forms = dom?.insecureForms || [];
  const withPassword = forms.filter((f) => f.hasPasswordField);
  const status = withPassword.length > 0 ? "danger" : forms.length > 0 ? "warn" : "safe";
  const summary =
    withPassword.length > 0
      ? `${withPassword.length} form(s) with a password field submit over HTTP.`
      : forms.length > 0
      ? `${forms.length} form(s) submit over HTTP.`
      : "No forms submitting over an insecure connection.";
  return {
    id: "forms",
    title: "Form submission security",
    status,
    summary,
    detail: forms.map((f) => `${f.action}${f.hasPasswordField ? " (has password field)" : ""}`),
  };
}

function gradeThirdParty(dom) {
  const domains = dom?.thirdPartyScripts || [];
  return {
    id: "thirdparty",
    title: "Third-party scripts",
    status: domains.length > 6 ? "warn" : "neutral",
    summary:
      domains.length > 0
        ? `${domains.length} external script domain(s) loaded on this page.`
        : "No third-party script sources detected.",
    detail: domains,
  };
}

function gradeVulnLibs(libs) {
  const vulnerable = libs.filter((l) => l.vulnerable);
  return {
    id: "libs",
    title: "Known-vulnerable libraries",
    status: vulnerable.length > 0 ? "danger" : libs.length > 0 ? "safe" : "neutral",
    summary:
      vulnerable.length > 0
        ? `${vulnerable.length} detected librar${vulnerable.length === 1 ? "y" : "ies"} below the safe version.`
        : libs.length > 0
        ? `${libs.length} librar${libs.length === 1 ? "y" : "ies"} detected, all at safe versions.`
        : "No signatures matched (this checks a small illustrative set, not a full CVE database).",
    detail: libs.map(
      (l) =>
        `${l.name} ${l.version} — ${l.vulnerable ? `below safe min ${l.safeMin}. ${l.note}` : "OK"}`
    ),
  };
}

function scoreFromChecks(checks) {
  let score = 100;
  const weights = { danger: 15, warn: 5 };
  for (const c of checks) {
    if (c.status === "danger") score -= weights.danger;
    if (c.status === "warn") score -= weights.warn;
  }
  return Math.max(0, Math.min(100, score));
}

function overallStatus(score) {
  if (score >= 85) return { status: "safe", label: "Strong" };
  if (score >= 65) return { status: "warn", label: "Good, with gaps" };
  if (score >= 40) return { status: "warn", label: "Needs attention" };
  return { status: "danger", label: "Weak" };
}

function renderPermissionDetail(permissions) {
  const rows = Object.entries(permissions)
    .map(
      ([name, state]) =>
        `<div class="perm-row"><span>${name}</span><span class="perm-state ${state}">${state}</span></div>`
    )
    .join("");
  return `<div>${rows}</div>`;
}

function renderCheck(check) {
  const div = document.createElement("div");
  div.className = `check ${check.status}`;
  const statusLabel = { safe: "OK", warn: "WARN", danger: "RISK", neutral: "INFO" }[check.status];

  let detailHtml = "";
  if (check.isPermissions) {
    detailHtml = renderPermissionDetail(check.permissions);
  } else if (check.detail && check.detail.length > 0) {
    detailHtml = `<ul>${check.detail.map((d) => `<li>${escapeHtml(d)}</li>`).join("")}</ul>`;
  }

  div.innerHTML = `
    <div class="check-head">
      <span class="check-title">${check.title}</span>
      <span class="check-status">${statusLabel}</span>
    </div>
    <div class="check-summary">${check.summary}</div>
    ${detailHtml ? `<div class="check-detail">${detailHtml}</div>` : ""}
  `;

  if (detailHtml) {
    div.addEventListener("click", () => div.classList.toggle("open"));
  }
  return div;
}

function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = str;
  return d.innerHTML;
}

async function runScan() {
  loadingEl.style.display = "block";
  checksEl.innerHTML = "";
  checksEl.appendChild(loadingEl);
  scoreLabelEl.textContent = "Scanning…";

  const tab = await getActiveTab();
  if (!tab || !tab.url || !tab.url.startsWith("http")) {
    loadingEl.textContent = "Open a regular http(s) page to scan it.";
    scoreNumEl.textContent = "--";
    scoreLabelEl.textContent = "Not scannable";
    return;
  }

  const url = new URL(tab.url);
  scoreDomainEl.textContent = url.hostname;

  const [headerData, cookies, dom, libs] = await Promise.all([
    sendMessage({ type: "GET_HEADERS", tabId: tab.id }),
    sendMessage({ type: "GET_COOKIES", domain: url.hostname }),
    scanDom(tab.id),
    scanVulnerableLibs(tab.id),
  ]);

  const isHttps = url.protocol === "https:";
  const checks = [
    {
      id: "https",
      title: "Connection (HTTPS)",
      status: isHttps ? "safe" : "danger",
      summary: isHttps
        ? "This page is loaded over HTTPS."
        : "This page is loaded over plain HTTP — traffic isn't encrypted.",
    },
    ...gradeHeaders(headerData, isHttps),
    gradeCookies(cookies, isHttps),
    gradePermissions(dom?.permissions),
    gradeMixedContent(dom),
    gradeForms(dom),
    gradeThirdParty(dom),
    gradeVulnLibs(libs),
  ];

  const score = scoreFromChecks(checks);
  const { status, label } = overallStatus(score);

  scoreNumEl.textContent = score;
  scoreLabelEl.textContent = label;
  scoreDotEl.className = `dot ${status}`;

  checksEl.innerHTML = "";
  checks.forEach((c) => checksEl.appendChild(renderCheck(c)));
}

rescanBtn.addEventListener("click", runScan);
runScan();
