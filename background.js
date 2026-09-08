// background.js
// Captures response headers for the top-level document of each tab, so the
// popup can grade the site's security headers without re-fetching the page.

const tabHeaderCache = new Map(); // tabId -> { url, headers: {name: value}, status }

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== "main_frame") return;
    const headerMap = {};
    for (const h of details.responseHeaders || []) {
      headerMap[h.name.toLowerCase()] = h.value;
    }
    tabHeaderCache.set(details.tabId, {
      url: details.url,
      headers: headerMap,
      statusCode: details.statusCode,
    });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Clear stale cache when a tab navigates away or closes.
chrome.webNavigation.onBeforeNavigate?.addListener((details) => {
  if (details.frameId === 0) tabHeaderCache.delete(details.tabId);
});
chrome.tabs.onRemoved.addListener((tabId) => tabHeaderCache.delete(tabId));

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_HEADERS") {
    const tabId = message.tabId;
    const cached = tabHeaderCache.get(tabId);
    sendResponse(cached || null);
    return true;
  }

  if (message.type === "GET_COOKIES") {
    chrome.cookies.getAll({ domain: message.domain }, (cookies) => {
      sendResponse(
        cookies.map((c) => ({
          name: c.name,
          secure: c.secure,
          httpOnly: c.httpOnly,
          sameSite: c.sameSite,
          session: c.session,
        }))
      );
    });
    return true; // async response
  }
});
