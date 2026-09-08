# Site Security Inspector

A Manifest V3 browser extension (Chrome + Firefox) that audits the site you're
currently viewing across several security angles and gives it a score out of 100.

## What it checks

| Check | What it looks at |
|---|---|
| Connection | Whether the page is served over HTTPS |
| Security headers | `Content-Security-Policy`, `X-Content-Type-Options`, clickjacking protection (`X-Frame-Options` / `frame-ancestors`), `Strict-Transport-Security`, `Referrer-Policy` |
| Cookies | `Secure`, `SameSite` flags on cookies set for the domain |
| Site permissions | Live grant state (granted / denied / prompt) for geolocation, camera, microphone, notifications, clipboard, MIDI |
| Mixed content | HTTP resources (images, scripts, iframes, etc.) loaded on an HTTPS page |
| Form security | Forms — especially ones with a password field — submitting over plain HTTP |
| Third-party scripts | External domains the page loads JavaScript from |
| Known-vulnerable libraries | A small illustrative signature set (jQuery, Lodash, AngularJS, Moment.js, Bootstrap) checked against known-safe minimum versions |

The vulnerable-library check is intentionally small and educational — it is
**not** a replacement for tools like Retire.js, `npm audit`, or Snyk.

## How it works

- `background.js` is a service worker that listens for response headers via
  `chrome.webRequest` and caches them per tab, and relays cookie lookups.
- `popup/popup.js` runs when you open the toolbar icon. It reads the cached
  headers, queries cookies, and injects two small scripts into the current
  tab on demand via `chrome.scripting.executeScript`:
  - `lib/dom-scan.js` runs in the page's isolated content-script world to
    check the DOM (mixed content, forms, third-party scripts) and query
    live permission state.
  - `lib/vulnerable-libs.js` runs in the page's **main** world (`world:
    "MAIN"`) because it needs to see page-level globals like `window.jQuery`,
    which aren't visible from an isolated content-script context.
- Each check gets a `safe` / `warn` / `danger` / `neutral` status; the score
  is 100 minus weighted deductions per issue.

## Install (development / unpacked)

**Chrome / Edge / Brave:**
1. Go to `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select the `security-inspector` folder.
4. Pin the extension, then click its icon on any `http(s)://` page.

**Firefox:**
1. Go to `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on…**.
3. Select `manifest.json` inside the `security-inspector` folder.
   (Temporary add-ons are removed when Firefox restarts — for a permanent
   install you'd package and sign it via addons.mozilla.org.)

## Notes & limitations

- Header data only becomes available once the browser has seen the page's
  response, so the very first scan right after a fresh page load may show
  headers as missing until you rescan.
- The permission check reflects whatever the browser already knows for that
  origin; permissions the user has never been asked about show as `prompt`.
- This tool is for awareness/education, not a certified security audit.


Disclaimer :- Use it at your own risk .The developer will not be responsible for any issue or problem caused by this extension and you hereby confirms yourself that you are the only responsible one for any circumstances.


Developed By:- ADITYA KUMAR JHA

You can follow me on:-
https://www.linkedin.com/in/adityakumarjha999
in/adityakumarjha999
https://www.salesforce.com/trailblazer/profile
https://unstop.com/u/technadi29148
https://leetcode.com/u/AdityaKumar77/
