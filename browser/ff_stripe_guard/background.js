// AI Hunter Sentinel — Background blocker with brand config (Stripe + PayPal)

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
