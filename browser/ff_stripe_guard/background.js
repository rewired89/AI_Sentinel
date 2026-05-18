// AI Hunter Sentinel — Privacy Guard
// Handles: phishing brand blocking, Sentinel proxy routing, deanon alerts.

// --- Config loading ---
let BRANDS = [
  { name: "stripe", official: ["stripe.com"], keywords: ["stripe", "str1pe"] },
  { name: "paypal", official: ["paypal.com"], keywords: ["paypal", "paypa1", "pay-pal", "xn--pay"] }
];

async function loadBrands() {
  try {
    const url = browser.runtime.getURL("brands.json");
    const res = await fetch(url);
    if (res.ok) {
      const data = await res.json();
      if (data && Array.isArray(data.brands)) BRANDS = data.brands;
    }
  } catch (_) { /* keep defaults */ }
}
loadBrands();

// --- Helpers ---
function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } }

function isOfficial(host, officialList) {
  if (!host) return false;
  host = host.toLowerCase();
  return officialList.some(dom => host === dom || host.endsWith("." + dom));
}

function matchBrand(host) {
  if (!host) return null;
  const h = host.toLowerCase();
  for (const b of BRANDS) {
    // Official allowlist
    if (isOfficial(h, b.official)) return { brand: b.name, official: true, hit: null };
    // Lookalike keywords
    for (const kw of b.keywords) {
      if (h.includes(kw) && !isOfficial(h, b.official)) {
        return { brand: b.name, official: false, hit: kw };
      }
    }
  }
  return null;
}

// --- Notifications ---
function showNotification(host, brand) {
  try {
    browser.notifications.create({
      type: "basic",
      iconUrl: "icons/warn-48.png",
      title: "AI Hunter Sentinel",
      message: `Blocked: ${host}\nPossible ${brand} phishing site.`
    });
  } catch (_) {}
}

// Exposed to content scripts (Gmail toast -> native notification)
browser.runtime.onMessage.addListener((msg) => {
  if (msg && msg.type === "notify" && msg.host && msg.brand) {
    showNotification(msg.host, msg.brand);
  }
});

// --- Redirect target ---
function blockedPageUrl(host, brand) {
  const base = browser.runtime.getURL("blocked.html");
  const qp = new URLSearchParams({ host: host || "", brand: brand || "site" }).toString();
  return `${base}?${qp}`;
}

// --- Network-layer block ---
browser.webRequest.onBeforeRequest.addListener(
  (req) => {
    const host = hostOf(req.url);
    const m = matchBrand(host);
    if (m && !m.official) {
      showNotification(host, m.brand);
      return { redirectUrl: blockedPageUrl(host, m.brand) };
    }
    return { cancel: false };
  },
  { urls: ["<all_urls>"], types: ["main_frame", "sub_frame"] },
  ["blocking"]
);

// --- Fallback: if page already started, redirect anyway ---
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!changeInfo.url && changeInfo.status !== "loading") return;
  const url = changeInfo.url || tab.url || "";
  const host = hostOf(url);
  const m = matchBrand(host);
  if (m && !m.official) {
    showNotification(host, m.brand);
    try { browser.tabs.update(tabId, { url: blockedPageUrl(host, m.brand) }); }
    catch { browser.tabs.remove(tabId).catch(() => {}); }
  }
});

// ---------------------------------------------------------------------------
// Sentinel Proxy routing
// The AI Sentinel privacy proxy runs on 127.0.0.1:8877 and routes all traffic
// through the Nym mixnet while scanning for threats. Configure Firefox to use
// it whenever it is reachable; fall back to direct when it isn't running.
// ---------------------------------------------------------------------------

const SENTINEL_PROXY = { host: "127.0.0.1", port: 8877 };

async function isSentinelProxyUp() {
  // We can't open raw TCP sockets from an extension; instead we try a fetch to
  // the mitmproxy magic-host URL — if the proxy is up it responds with its CA
  // info page; if down the fetch fails. Timeout of 1 s keeps this snappy.
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), 1000);
    await fetch("http://mitm.it/", { signal: ctrl.signal, mode: "no-cors" });
    clearTimeout(tid);
    return true;
  } catch {
    return false;
  }
}

async function applyProxySettings() {
  const up = await isSentinelProxyUp();
  if (up) {
    browser.proxy.settings.set({
      value: {
        proxyType:   "manual",
        http:        `${SENTINEL_PROXY.host}:${SENTINEL_PROXY.port}`,
        ssl:         `${SENTINEL_PROXY.host}:${SENTINEL_PROXY.port}`,
        socks:       `${SENTINEL_PROXY.host}:${SENTINEL_PROXY.port}`,
        socksVersion: 5,
        proxyDNS:    true,
      },
      scope: "regular",
    }).catch(() => {});
    console.log("[sentinel] Proxy active → 127.0.0.1:8877 (Nym mixnet routing)");
  } else {
    browser.proxy.settings.clear({ scope: "regular" }).catch(() => {});
    console.log("[sentinel] Proxy not detected — using direct connection.");
  }
}

// Check on startup and every 30 s so the extension adapts when the user
// starts or stops the privacy layer without restarting Firefox.
applyProxySettings();
setInterval(applyProxySettings, 30_000);

// ---------------------------------------------------------------------------
// De-anonymization alert
// The scanning proxy injects X-Sentinel-Warning into any response where it
// detects fingerprinting or IP-leak JavaScript. We intercept that header here
// and show the user a native notification with the specific technique caught.
// ---------------------------------------------------------------------------

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const warning = details.responseHeaders?.find(
      (h) => h.name.toLowerCase() === "x-sentinel-warning"
    );
    if (!warning) return {};

    const value   = warning.value || "";
    const host    = hostOf(details.url);
    const cats    = value.replace(/^deanon:/, "").split(",").join(", ");

    try {
      browser.notifications.create({
        type:     "basic",
        iconUrl:  "icons/warn-48.png",
        title:    "AI Sentinel — De-Anonymization Attempt Blocked",
        message:  `${host} tried: ${cats}`,
      });
    } catch (_) {}

    // Strip the header before it reaches the page — no need to expose internals.
    return {
      responseHeaders: details.responseHeaders.filter(
        (h) => h.name.toLowerCase() !== "x-sentinel-warning"
      ),
    };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "responseHeaders"]
);
