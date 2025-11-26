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
function addToolsHomeButton() {
  try {
    if (!location.pathname || !location.pathname.startsWith("/tools/")) return;
    const container = document.querySelector(".container.page");
    if (!container) return;
    const header = container.querySelector(".header");
    if (!header) return;
    const existing = container.querySelector(".tools-home-link");
    if (existing) return;
    const row = document.createElement("div");
    row.className = "row tools-home-link";
    const a = document.createElement("a");
    a.href = "/";
    a.className = "btn ghost";
    a.textContent = "← Back to home";
    row.appendChild(a);
    header.insertAdjacentElement("afterend", row);
  } catch (e) {
    console.error("tools home button error", e);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  bindSearch();
  enhancePasswords();
  addToolsHomeButton();
  generateIconBackground().catch((e) => console.error("bg error (dom):", e));
});
window.addEventListener("load", () => {
  if (!document.body.style.backgroundImage) {
    generateIconBackground().catch((e) => console.error("bg error (load):", e));
  }
});

// Random background generator using local SVG icons
async function generateIconBackground() {
  // Immediate CSS fallback so there's always a pattern visible
  const bg = getComputedStyle(document.documentElement).getPropertyValue("--bg").trim() || "#0b0f14";
  document.body.style.backgroundColor = bg;
  document.body.style.backgroundImage = "radial-gradient(rgba(255,255,255,.12) 2px, transparent 2px)";
  document.body.style.backgroundRepeat = "repeat";
  document.body.style.backgroundSize = "24px 24px";
  document.body.style.backgroundPosition = "0 0";
  document.body.style.backgroundAttachment = "scroll";
  
  // Default fallback icons in case the API call fails
  const defaultIcons = [
    "SVG icons/acrobat-reader-svgrepo-com.svg",
    "SVG icons/android-svgrepo-com.svg",
    "SVG icons/arch-svgrepo-com.svg",
    "SVG icons/code-editor-svgrepo-com.svg",
    "SVG icons/code-pull-request-svgrepo-com.svg",
    "SVG icons/github-svgrepo-com.svg",
    "SVG icons/laptop-signal-svgrepo-com.svg",
    "SVG icons/linux-svgrepo-com.svg",
    "SVG icons/programming-svgrepo-com.svg",
    "SVG icons/programming-svgrepo-com (1).svg",
    "SVG icons/python-svgrepo-com.svg",
    "SVG icons/terminal-powershell-svgrepo-com.svg",
  ];

  let iconFiles = [];
  try {
    // Try to fetch the list of icons from the API
    const response = await fetch('/api/icons');
    if (response.ok) {
      const data = await response.json();
      if (Array.isArray(data.icons) && data.icons.length > 0) {
        iconFiles = data.icons.map(icon => `/assets/${icon}`);
      } else {
        throw new Error('No icons returned from API');
      }
    } else {
      throw new Error(`API returned ${response.status}`);
    }
  } catch (error) {
    console.warn('Failed to fetch icon list from API, using default icons:', error);
    iconFiles = defaultIcons.map(icon => `/assets/${icon}`);
  }

  // Encode paths to handle spaces and special characters
  const paths = iconFiles.map(p => 
    encodeURI(p).replace(/\(/g, "%28").replace(/\)/g, "%29")
  );
  async function loadSvgAsImage(src) {
    try {
      const res = await fetch(src);
      if (!res.ok) return null;
      const txt = await res.text();
      const dataUrl = "data:image/svg+xml;charset=UTF-8," + encodeURIComponent(txt);
      return await new Promise((resolve) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => resolve(null);
        img.src = dataUrl;
      });
    } catch {
      return null;
    }
  }
  const images = await Promise.all(paths.map((p) => loadSvgAsImage(p)));
  const icons = images.filter(Boolean);
  if (!icons.length) {
    console.warn("bg: no icons loaded, drawing fallback pattern");
    const tile = 360;
    const canvas = document.createElement("canvas");
    canvas.width = tile;
    canvas.height = tile;
    const ctx = canvas.getContext("2d");
    const bg = getComputedStyle(document.documentElement).getPropertyValue("--bg").trim() || "#0b0f14";
    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, tile, tile);
    // subtle dot grid fallback
    ctx.fillStyle = "rgba(255,255,255,0.12)";
    for (let y = 10; y < tile; y += 24) {
      for (let x = 10; x < tile; x += 24) {
        ctx.beginPath();
        ctx.arc(x + (Math.random()*4-2), y + (Math.random()*4-2), 1.8, 0, Math.PI*2);
        ctx.fill();
      }
    }
    document.body.style.backgroundColor = bg;
    let dataUrl = "";
    try { dataUrl = canvas.toDataURL("image/png"); } catch {}
    if (dataUrl) {
      document.body.style.backgroundImage = `url(${dataUrl})`;
      document.body.style.backgroundRepeat = "repeat";
      document.body.style.backgroundAttachment = "fixed";
      document.body.style.backgroundSize = `${tile}px ${tile}px`;
      document.body.style.backgroundPosition = "0 0";
      return;
    }
    // If even this fails, bail silently
    return;
  }

  // Generate a seamless-ish tile and repeat it
  const tile = 360; // tile size px (controls density)
  const canvas = document.createElement("canvas");
  canvas.width = tile;
  canvas.height = tile;
  const ctx = canvas.getContext("2d");

  // Background base color from CSS var (reuse earlier bg variable)
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, tile, tile);

  // Place icons with small gaps and slight rotation
  const placements = [];
  const count = 100; // much denser
  const minGap = 3; // tighter gaps
  function overlaps(x, y, w, h) {
    for (const r of placements) {
      if (x < r.x + r.w + minGap && x + w + minGap > r.x && y < r.y + r.h + minGap && y + h + minGap > r.y) {
        return true;
      }
    }
    return false;
  }

  for (let i = 0; i < count; i++) {
    const img = icons[(Math.random() * icons.length) | 0];
    const size = 18 + Math.random() * 26; // ~18..44 px
    const w = size;
    const h = size;
    let placed = false;
    for (let tries = 0; tries < 70 && !placed; tries++) {
      const x = Math.random() * (tile - w);
      const y = Math.random() * (tile - h);
      if (!overlaps(x, y, w, h)) {
        const rot = (Math.random() - 0.5) * (Math.PI / 8); // ~±22.5°
        drawTintedIcon(ctx, img, x, y, w, h, "#ffffff", 0.14, rot);
        placements.push({ x, y, w, h });
        placed = true;
      }
    }
  }

  document.body.style.backgroundColor = bg;
  let dataUrl = "";
  try { dataUrl = canvas.toDataURL("image/png"); } catch {}
  if (!dataUrl) {
    // CSS gradient fallback tile
    document.body.style.backgroundImage = "radial-gradient(rgba(255,255,255,.08) 1px, transparent 1px)";
    document.body.style.backgroundRepeat = "repeat";
    document.body.style.backgroundSize = "24px 24px";
    document.body.style.backgroundPosition = "0 0";
    document.body.style.backgroundAttachment = "scroll";
    return;
  }
  document.body.style.backgroundImage = `url(${dataUrl})`;
  document.body.style.backgroundRepeat = "repeat";
  document.body.style.backgroundAttachment = "scroll";
  document.body.style.backgroundSize = `${tile}px ${tile}px`;
  document.body.style.backgroundPosition = "0 0";
}

function drawTintedIcon(ctx, img, dx, dy, dw, dh, color, alpha, rotationRad) {
  // Recolor the SVG to a single tint using an offscreen canvas as a mask
  const off = document.createElement("canvas");
  off.width = Math.ceil(dw);
  off.height = Math.ceil(dh);
  const c2 = off.getContext("2d");
  c2.clearRect(0, 0, off.width, off.height);
  // Fill with tint color at desired alpha
  c2.globalAlpha = alpha;
  c2.fillStyle = color;
  c2.fillRect(0, 0, off.width, off.height);
  // Use the SVG as alpha mask
  c2.globalCompositeOperation = "destination-in";
  c2.drawImage(img, 0, 0, off.width, off.height);

  ctx.save();
  ctx.translate(dx + dw / 2, dy + dh / 2);
  ctx.rotate(rotationRad);
  ctx.drawImage(off, -dw / 2, -dh / 2, dw, dh);
  ctx.restore();
}
window.generateIconBackground = generateIconBackground;
