// Gmail pre-click protection — AI Hunter Sentinel
(function () {
  function isOfficialStripe(host) {
    const h = (host || "").toLowerCase();
    return h === "stripe.com" || h.endsWith(".stripe.com");
  }
  function isImposter(host) {
    const h = (host || "").toLowerCase();
    if (!h) return false;
    if (isOfficialStripe(h)) return false;
    if (h.includes("stripe")) return true;
    if (h.includes("str1pe") || h.includes("xn--")) return true;
    return false;
  }
  function hostOf(u) { try { return new URL(u).hostname; } catch { return ""; } }

  // Robust toast (attach to body, keep on top)
  function showToast(msg) {
    const id = "aihunter-sentinel-toast";
    let el = document.getElementById(id);
    if (!el) {
      el = document.createElement("div");
      el.id = id;
      Object.assign(el.style, {
        position: "fixed",
        right: "16px",
        bottom: "16px",
        zIndex: "2147483647",
        maxWidth: "420px",
        background: "#111827",
        color: "#fff",
        padding: "12px 14px",
        borderRadius: "10px",
        boxShadow: "0 6px 20px rgba(0,0,0,.35)",
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif",
        fontSize: "14px",
        lineHeight: "1.35",
        display: "flex",
        alignItems: "flex-start",
        gap: "10px",
        border: "1px solid rgba(255,255,255,.1)",
        opacity: "1",
        transition: "opacity 0.5s ease",
        pointerEvents: "none"
      });
      const icon = document.createElement("span");
      icon.textContent = "🛡️";
      icon.style.flex = "0 0 auto";
      const text = document.createElement("div");
      text.id = id + "-text";
      text.style.flex = "1 1 auto";
      el.appendChild(icon); el.appendChild(text);
    }
    if (!document.body.contains(el)) document.body.appendChild(el);
    const textEl = document.getElementById(id + "-text");
    textEl.textContent = msg || "Security alert.";
    el.style.opacity = "1";
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.style.opacity = "0"; }, 5000);
  }

  function handleNav(ev, url) {
    const host = hostOf(url);
    if (!isImposter(host)) return;
    ev.preventDefault();
    ev.stopPropagation();

    // In-page toast
    showToast(`AI Hunter Sentinel blocked: ${host}. Possible Stripe phishing site.`);

    // Native Firefox notification via background bridge
    try { browser.runtime.sendMessage({ type: "notify", host }); } catch {}

    // Open explanation page
    const blocked = browser.runtime.getURL("blocked.html") + "?host=" + encodeURIComponent(host);
    window.open(blocked, "_blank", "noopener");
  }

  document.addEventListener("click", (ev) => {
    const a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
    if (!a) return;
    handleNav(ev, a.getAttribute("href") || "");
  }, true);

  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    const a = document.activeElement && document.activeElement.closest
      ? document.activeElement.closest("a[href]")
      : null;
    if (!a) return;
    handleNav(ev, a.getAttribute("href") || "");
  }, true);

  // Mark suspicious links
  const markLinks = () => {
    document.querySelectorAll('a[href]').forEach(a => {
      const host = hostOf(a.getAttribute('href') || "");
      if (isImposter(host) && !a.dataset.aihunterSentinelFlagged) {
        a.dataset.aihunterSentinelFlagged = "1";
        a.style.outline = "2px solid #d33";
        a.title = "Possible Stripe phishing link — blocked by AI Hunter Sentinel";
      }
    });
  };

  const target = document.body || document.documentElement;
  const obs = new MutationObserver(() => markLinks());
  obs.observe(target, { subtree: true, childList: true });
  markLinks();
})();
