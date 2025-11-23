function $(s, root = document) {
  return root.querySelector(s);
}
function $all(s, root = document) {
  return Array.from(root.querySelectorAll(s));
}
function toast(msg, type) {
  // Infer type if not provided
  if (!type) {
    const m = String(msg || "").toLowerCase();
    if (/invalid|fail|error|unreach|unsupported|denied|not configured/.test(m))
      type = "error";
    else if (/success|copied|valid|match/.test(m)) type = "success";
    else if (/warn|select|please|missing|empty/.test(m)) type = "warning";
    else type = "info";
  }
  let t = $(".toast");
  if (!t) {
    t = document.createElement("div");
    t.className = "toast";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.classList.remove("success", "error", "warning", "info");
  t.classList.add(type);
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 1800);
}
function copyText(el) {
  navigator.clipboard.writeText(el.value || el.textContent || "").then(() => {
    toast("Copied", "success");
    const btn = document.activeElement;
    if (btn && btn.classList && btn.classList.contains("btn")) {
      btn.classList.remove("pulse");
      void btn.offsetWidth;
      btn.classList.add("pulse");
    }
  });
}
function encodeBase64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}
function decodeBase64(b64) {
  try {
    return decodeURIComponent(escape(atob(b64)));
  } catch (e) {
    return "";
  }
}
async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    let m = "Request failed";
    try {
      const e = await r.json();
      m = e.error || m;
    } catch {}
    throw new Error(m);
  }
  return r.json();
}
function bindSearch() {
  const q = $("#search");
  if (!q) return;
  q.addEventListener("input", () => {
    const v = q.value.toLowerCase();
    $all(".card").forEach((c) => {
      const t = c.dataset.tags || "";
      const n = c.querySelector(".title")?.textContent.toLowerCase() || "";
      c.style.display = t.includes(v) || n.includes(v) ? "block" : "none";
    });
  });
}
function enhancePasswords() {
  $all('input[type="password"]').forEach((inp) => {
    if (inp.closest(".pwd-wrap")) return;
    const wrap = document.createElement("div");
    wrap.className = "pwd-wrap";
    inp.parentNode.insertBefore(wrap, inp);
    wrap.appendChild(inp);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "pwd-toggle";
    btn.innerHTML =
      '<svg viewBox="0 0 24 24"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12Z"/><path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/><path class="slash" d="M3 3L21 21"/></svg>';
    btn.addEventListener("click", () => {
      const isPwd = inp.type === "password";
      inp.type = isPwd ? "text" : "password";
      btn.classList.toggle("on", isPwd);
    });
    wrap.appendChild(btn);
  });
}
window.addEventListener("DOMContentLoaded", () => {
  bindSearch();
  enhancePasswords();
});
