// dom-scan.js
// Runs in the isolated world (default content-script context) via
// chrome.scripting.executeScript. Standard Web APIs like `document` and
// `navigator.permissions` are visible here, so no MAIN-world access is
// needed for these checks.

(function () {
  const PERMISSION_NAMES = [
    "geolocation",
    "camera",
    "microphone",
    "notifications",
    "clipboard-read",
    "clipboard-write",
    "midi",
  ];

  async function scanPermissions() {
    const results = {};
    for (const name of PERMISSION_NAMES) {
      try {
        const status = await navigator.permissions.query({ name });
        results[name] = status.state; // "granted" | "denied" | "prompt"
      } catch (e) {
        results[name] = "unsupported";
      }
    }
    return results;
  }

  function scanMixedContent() {
    if (location.protocol !== "https:") return [];
    const insecure = [];
    document.querySelectorAll("img, script, iframe, link, source").forEach((el) => {
      const src = el.src || el.href;
      if (src && src.startsWith("http://")) {
        insecure.push({ tag: el.tagName.toLowerCase(), url: src });
      }
    });
    return insecure.slice(0, 25);
  }

  function scanThirdPartyScripts() {
    const host = location.hostname;
    const thirdParty = new Set();
    document.querySelectorAll("script[src]").forEach((el) => {
      try {
        const u = new URL(el.src, location.href);
        if (u.hostname !== host) thirdParty.add(u.hostname);
      } catch (e) {
        /* ignore malformed URLs */
      }
    });
    return Array.from(thirdParty);
  }

  function scanInsecureForms() {
    const issues = [];
    document.querySelectorAll("form").forEach((form) => {
      const action = form.getAttribute("action") || location.href;
      try {
        const u = new URL(action, location.href);
        const hasPasswordField = !!form.querySelector('input[type="password"]');
        if (u.protocol === "http:" && (hasPasswordField || location.protocol === "https:")) {
          issues.push({ action: u.href, hasPasswordField });
        }
      } catch (e) {
        /* ignore malformed action URLs */
      }
    });
    return issues;
  }

  window.__secInspectorScanDom = async function () {
    return {
      isHttps: location.protocol === "https:",
      mixedContent: scanMixedContent(),
      thirdPartyScripts: scanThirdPartyScripts(),
      insecureForms: scanInsecureForms(),
      permissions: await scanPermissions(),
    };
  };
})();
