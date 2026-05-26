// digger docs — chrome injection + search + TOC + anchors + copy + nav.
// All zero-dependency, no build step. Each page sets <body data-page="...">
// and this script does the rest.

(function () {

  // ---- single source of truth for site nav ---- //
  const NAV_GROUPS = [
    { title: "Start here", items: [
      { id: "index",            href: "index.html",            label: "Overview" },
      { id: "getting-started",  href: "getting-started.html",  label: "Getting started" },
      { id: "cli",              href: "cli.html",              label: "CLI reference" },
    ]},
    { title: "Core concepts", items: [
      { id: "architecture",     href: "architecture.html",     label: "Architecture" },
      { id: "evidence-store",   href: "evidence-store.html",   label: "Evidence store" },
      { id: "collectors",       href: "collectors.html",       label: "Collectors" },
      { id: "detectors",        href: "detectors.html",        label: "Detectors" },
      { id: "diff",             href: "diff.html",             label: "Case diff" },
      { id: "hunts",            href: "hunts.html",            label: "Threat hunting" },
      { id: "memory",           href: "memory.html",           label: "Memory forensics" },
      { id: "firewall-audit",   href: "firewall-audit.html",   label: "Firewall audit + remediation" },
    ]},
    { title: "Counter-offensive", items: [
      { id: "decepticon-counter", href: "decepticon-counter.html", label: "Decepticon countermeasures" },
      { id: "browser-scanner",  href: "browser-scanner.html",  label: "Browser scanner" },
      { id: "chromium-unpatched", href: "chromium-unpatched.html", label: "Unpatched Chromium bugs" },
    ]},
    { title: "Specialized auditors", items: [
      { id: "idp",                href: "idp.html",                label: "IdP audit-log observability" },
      { id: "slsa",               href: "slsa.html",               label: "SLSA provenance audit" },
      { id: "android",            href: "android.html",            label: "Android forensics (adb)" },
      { id: "mcp",                href: "mcp.html",                label: "MCP config audit" },
      { id: "ci-workflow-audit",  href: "ci-workflow-audit.html",  label: "CI/CD workflow audit" },
    ]},
    { title: "Threat intel", items: [
      { id: "intel",            href: "intel.html",            label: "Live feeds" },
      { id: "ai-triage",        href: "ai-triage.html",        label: "AI triage" },
      { id: "exchange",         href: "exchange.html",         label: "STIX / MISP / ATT&CK" },
      { id: "sigma",            href: "sigma.html",            label: "Sigma rules" },
      { id: "genrule",          href: "genrule.html",          label: "Generate Sigma from findings" },
      { id: "loki",             href: "loki.html",             label: "LOKI / signature-base" },
    ]},
    { title: "Gov-grade & compliance", items: [
      { id: "ethics",           href: "ethics.html",           label: "Ethical contract" },
      { id: "pqc",              href: "pqc.html",              label: "Post-quantum crypto" },
      { id: "fips",             href: "fips.html",             label: "FIPS 140-3 mode" },
      { id: "compliance",       href: "compliance.html",       label: "Compliance frameworks" },
      { id: "soc2",             href: "soc2.html",             label: "SOC 2 audit prep" },
      { id: "tradecraft",       href: "tradecraft.html",       label: "Analytic tradecraft" },
      { id: "forensics-grade",  href: "forensics-grade.html",  label: "ISO 27037 chain of custody" },
      { id: "opsec",            href: "opsec.html",            label: "Operator opsec" },
    ]},
    { title: "Extending", items: [
      { id: "extending",        href: "extending.html",        label: "Writing new modules" },
      { id: "gotchas",          href: "gotchas.html",          label: "Gotchas" },
    ]},
  ];

  // Flat list preserving display order — used for prev/next page navigation.
  const FLAT_NAV = NAV_GROUPS.flatMap(g => g.items);

  const LOGO_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 280" aria-label="digger">
  <defs>
    <radialGradient id="bg" cx="50%" cy="40%" r="70%">
      <stop offset="0%" stop-color="#161a22"/><stop offset="100%" stop-color="#05070a"/>
    </radialGradient>
    <linearGradient id="bone" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#f3efe3"/><stop offset="100%" stop-color="#bdb6a1"/>
    </linearGradient>
    <linearGradient id="steel" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#c9cdd5"/><stop offset="100%" stop-color="#5a6068"/>
    </linearGradient>
  </defs>
  <circle cx="120" cy="140" r="115" fill="url(#bg)" stroke="#e8e3d4" stroke-width="3"/>
  <circle cx="120" cy="140" r="105" fill="none" stroke="#3a3f48" stroke-width="1"/>
  <g transform="rotate(-32 120 140)">
    <rect x="116" y="35" width="8" height="170" fill="url(#steel)" stroke="#2a2e36" stroke-width="1.2"/>
    <rect x="100" y="28" width="40" height="14" rx="4" fill="url(#steel)" stroke="#2a2e36" stroke-width="1.2"/>
    <path d="M 100 200 L 140 200 L 152 250 L 120 268 L 88 250 Z" fill="url(#steel)" stroke="#2a2e36" stroke-width="1.4"/>
    <line x1="120" y1="208" x2="120" y2="258" stroke="#2a2e36" stroke-width="1"/>
  </g>
  <ellipse cx="120" cy="92" rx="34" ry="38" fill="url(#bone)" stroke="#5a5240" stroke-width="1.5"/>
  <ellipse cx="107" cy="90" rx="7" ry="9" fill="#05070a"/>
  <ellipse cx="133" cy="90" rx="7" ry="9" fill="#05070a"/>
  <path d="M 120 100 L 116 112 L 124 112 Z" fill="#05070a"/>
  <rect x="104" y="116" width="32" height="6" fill="#05070a"/>
  <g stroke="url(#bone)" stroke-width="2.5" fill="none">
    <line x1="120" y1="132" x2="120" y2="200"/>
    <path d="M 96 142 Q 120 152 144 142"/>
    <path d="M 92 154 Q 120 166 148 154"/>
    <path d="M 90 168 Q 120 180 150 168"/>
    <path d="M 92 182 Q 120 192 148 182"/>
  </g>
  <g stroke="url(#bone)" stroke-width="4" fill="none" stroke-linecap="round">
    <line x1="100" y1="138" x2="74" y2="118"/>
    <line x1="74" y1="118" x2="56" y2="90"/>
    <line x1="140" y1="138" x2="168" y2="160"/>
    <line x1="168" y1="160" x2="186" y2="186"/>
  </g>
  <circle cx="56" cy="90" r="5" fill="url(#bone)" stroke="#5a5240" stroke-width="1"/>
  <circle cx="186" cy="186" r="5" fill="url(#bone)" stroke="#5a5240" stroke-width="1"/>
</svg>`;

  // ---- helpers ---- //

  function slugify(text) {
    return (text || "")
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, "")
      .trim()
      .replace(/\s+/g, "-")
      .slice(0, 80);
  }

  function el(tag, attrs, children) {
    const e = document.createElement(tag);
    if (attrs) {
      for (const k in attrs) {
        if (k === "class") e.className = attrs[k];
        else if (k === "html") e.innerHTML = attrs[k];
        else if (k.startsWith("on")) e.addEventListener(k.slice(2).toLowerCase(), attrs[k]);
        else e.setAttribute(k, attrs[k]);
      }
    }
    for (const c of (children || [])) {
      if (c == null) continue;
      e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return e;
  }

  function escapeHtml(s) {
    return (s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function flash(node, text) {
    const original = node.textContent;
    node.textContent = text;
    node.classList.add("flashed");
    setTimeout(() => {
      node.textContent = original;
      node.classList.remove("flashed");
    }, 900);
  }

  // ---- topbar ---- //

  function injectTopbar() {
    let bar = document.getElementById("topbar");
    if (!bar) {
      bar = document.createElement("header");
      bar.id = "topbar";
      document.body.insertBefore(bar, document.body.firstChild);
    }
    bar.innerHTML = `
      <button class="hamburger" aria-label="toggle navigation" title="toggle navigation">
        <span></span><span></span><span></span>
      </button>
      <a class="logo" href="index.html">
        ${LOGO_SVG}
        <div>
          <strong>DIGGER</strong>
          <small>cross-platform forensics suite</small>
        </div>
      </a>
      <span class="spacer"></span>
      <button class="search-trigger" aria-label="search docs" title="search docs (press /)">
        <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
          <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" stroke-width="2"/>
          <line x1="16.5" y1="16.5" x2="22" y2="22" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        </svg>
        <span>Search</span>
        <kbd>/</kbd>
      </button>
      <a class="ext" href="cli.html">cli</a>
      <a class="ext" href="extending.html">extend</a>
    `;
    bar.querySelector(".hamburger").addEventListener("click", () => {
      document.body.classList.toggle("nav-open");
    });
    bar.querySelector(".search-trigger").addEventListener("click", openSearch);
  }

  // ---- sidebar ---- //

  function injectSidebar(activeId) {
    let side = document.getElementById("sidebar");
    if (!side) {
      side = document.createElement("aside");
      side.id = "sidebar";
      document.body.insertBefore(side, document.body.children[1] || null);
    }
    side.innerHTML = NAV_GROUPS.map(g => {
      const items = g.items.map(it => {
        const cls = it.id === activeId ? " class=\"active\"" : "";
        return `<a href="${it.href}"${cls}>${it.label}</a>`;
      }).join("");
      return `<div class="group"><h4>${g.title}</h4>${items}</div>`;
    }).join("");
    side.addEventListener("click", e => {
      if (e.target.tagName === "A") {
        document.body.classList.remove("nav-open");
      }
    });
  }

  // ---- on-page table of contents ---- //

  function injectTOC() {
    const main = document.querySelector("main");
    if (!main) return;
    const headings = main.querySelectorAll("h2, h3");
    if (headings.length < 2) return;
    const toc = document.createElement("aside");
    toc.id = "toc";
    toc.innerHTML = "<h4>On this page</h4>";
    const list = document.createElement("ul");
    headings.forEach(h => {
      if (!h.id) {
        h.id = slugify(h.textContent || "");
      }
      // anchor link icon (click to copy permalink)
      const anchor = el("a", {
        class: "heading-anchor",
        href: "#" + h.id,
        title: "copy link to section",
        "aria-label": "copy link",
      }, ["#"]);
      anchor.addEventListener("click", (ev) => {
        ev.preventDefault();
        const url = location.origin + location.pathname + "#" + h.id;
        if (navigator.clipboard) navigator.clipboard.writeText(url);
        history.replaceState(null, "", "#" + h.id);
        h.scrollIntoView({ behavior: "smooth", block: "start" });
        flash(anchor, "copied");
      });
      h.appendChild(anchor);
      const li = el("li", { class: h.tagName.toLowerCase() }, [
        el("a", { href: "#" + h.id }, [h.textContent.replace(/#$/, "").trim()]),
      ]);
      list.appendChild(li);
    });
    toc.appendChild(list);
    main.appendChild(toc);

    // scrollspy
    const links = toc.querySelectorAll("a");
    if (!("IntersectionObserver" in window)) return;
    const obs = new IntersectionObserver(entries => {
      entries.forEach(en => {
        if (en.isIntersecting) {
          const id = en.target.id;
          links.forEach(a => {
            a.classList.toggle("active", a.getAttribute("href") === "#" + id);
          });
        }
      });
    }, { rootMargin: "-30% 0px -65% 0px", threshold: 0 });
    headings.forEach(h => obs.observe(h));
  }

  // ---- copy-to-clipboard on every <pre><code> ---- //

  function injectCopyButtons() {
    document.querySelectorAll("main pre").forEach(pre => {
      const btn = el("button", {
        class: "copy-btn",
        title: "copy",
        "aria-label": "copy",
      }, ["copy"]);
      btn.addEventListener("click", () => {
        const text = (pre.querySelector("code") || pre).innerText;
        if (navigator.clipboard) navigator.clipboard.writeText(text);
        flash(btn, "copied");
      });
      pre.appendChild(btn);
    });
  }

  // ---- prev / next page navigation ---- //

  function injectPrevNext(activeId) {
    const main = document.querySelector("main");
    if (!main) return;
    const idx = FLAT_NAV.findIndex(it => it.id === activeId);
    if (idx < 0) return;
    const prev = FLAT_NAV[idx - 1];
    const next = FLAT_NAV[idx + 1];
    if (!prev && !next) return;
    const wrap = document.createElement("nav");
    wrap.id = "pagenav";
    if (prev) {
      const a = el("a", { href: prev.href, class: "prev" }, [
        el("span", { class: "label" }, ["← Previous"]),
        el("span", { class: "title" }, [prev.label]),
      ]);
      wrap.appendChild(a);
    } else {
      wrap.appendChild(el("span", { class: "spacer" }));
    }
    if (next) {
      const a = el("a", { href: next.href, class: "next" }, [
        el("span", { class: "label" }, ["Next →"]),
        el("span", { class: "title" }, [next.label]),
      ]);
      wrap.appendChild(a);
    }
    main.appendChild(wrap);
  }

  // ---- footer ---- //

  function injectFooter() {
    const main = document.querySelector("main");
    if (!main) return;
    const foot = el("footer", { id: "page-footer" }, []);
    foot.innerHTML = `
      <span>digger — cross-platform endpoint forensics suite</span>
      <span class="spacer"></span>
      <span class="hint">press <kbd>/</kbd> to search · <kbd>?</kbd> for shortcuts</span>
    `;
    main.appendChild(foot);
  }

  // ---- search ---- //

  let searchIndex = null;
  let searchModal = null;

  async function buildSearchIndex() {
    if (searchIndex) return searchIndex;
    const pages = FLAT_NAV;
    const results = await Promise.all(pages.map(async p => {
      try {
        const r = await fetch(p.href, { credentials: "same-origin" });
        if (!r.ok) return null;
        const html = await r.text();
        const doc = new DOMParser().parseFromString(html, "text/html");
        const titleEl = doc.querySelector("main h1") || doc.querySelector("title");
        const title = (titleEl ? titleEl.textContent : p.label).replace(/\s+/g, " ").trim();
        const subtitleEl = doc.querySelector("main h1 .subtitle");
        const subtitle = subtitleEl ? subtitleEl.textContent.trim() : "";
        const sections = [];
        doc.querySelectorAll("main h2, main h3").forEach(h => {
          const id = h.id || slugify(h.textContent || "");
          sections.push({
            id, level: h.tagName,
            text: (h.textContent || "").replace(/\s+/g, " ").trim(),
          });
        });
        const main = doc.querySelector("main");
        const bodyText = (main ? main.textContent : "")
          .replace(/\s+/g, " ").trim().toLowerCase();
        return { ...p, title, subtitle, sections, body: bodyText };
      } catch (e) {
        return null;
      }
    }));
    searchIndex = results.filter(Boolean);
    return searchIndex;
  }

  function scorePage(page, q) {
    // Split query into tokens; AND-match (every token must appear somewhere).
    const tokens = q.toLowerCase().split(/\s+/).filter(t => t.length >= 2);
    if (!tokens.length) return { page, score: 0, sectionHits: [], snippet: "" };
    const fullQ = tokens.join(" ");
    const titleLow = page.title.toLowerCase();
    const subtitleLow = page.subtitle.toLowerCase();
    let score = 0;
    const sectionHits = [];

    // Phrase boost — whole query as a phrase
    if (titleLow === fullQ) score += 120;
    else if (titleLow.includes(fullQ)) score += 70;
    if (subtitleLow.includes(fullQ)) score += 30;

    // Each token must hit somewhere in this page; otherwise score 0.
    for (const tok of tokens) {
      let here = 0;
      if (titleLow.includes(tok)) { score += 40; here++; }
      if (subtitleLow.includes(tok)) { score += 15; here++; }
      page.sections.forEach(s => {
        if (s.text.toLowerCase().includes(tok)) {
          score += 10;
          here++;
          if (!sectionHits.some(sh => sh.id === s.id)) sectionHits.push(s);
        }
      });
      let bodyCount = 0;
      let idx = page.body.indexOf(tok);
      while (idx !== -1 && bodyCount < 12) {
        bodyCount++;
        idx = page.body.indexOf(tok, idx + tok.length);
      }
      if (bodyCount) { score += bodyCount * 2; here++; }
      if (!here) return { page, score: 0, sectionHits: [], snippet: "" };
    }

    // Snippet around the strongest token (longest one usually most specific).
    const probe = tokens.slice().sort((a, b) => b.length - a.length)[0];
    let snippet = "";
    const first = page.body.indexOf(probe);
    if (first !== -1) {
      const start = Math.max(0, first - 50);
      const end = Math.min(page.body.length, first + probe.length + 90);
      snippet = (start > 0 ? "…" : "") + page.body.slice(start, end) + (end < page.body.length ? "…" : "");
    }
    return { page, score, sectionHits, snippet };
  }

  function highlight(text, q) {
    const safe = escapeHtml(text);
    if (!q) return safe;
    const tokens = q.toLowerCase().split(/\s+/).filter(t => t.length >= 2);
    if (!tokens.length) return safe;
    const re = new RegExp(
      "(" + tokens.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")",
      "ig"
    );
    return safe.replace(re, "<mark>$1</mark>");
  }

  function renderSearchResults(q) {
    const list = searchModal.querySelector(".sr-list");
    list.innerHTML = "";
    if (!q || q.length < 2) {
      list.innerHTML = `
        <div class='sr-hint'>
          <p style="margin:0 0 10px"><strong>Search digger docs.</strong></p>
          <ul style="margin:0;padding-left:18px;line-height:1.7">
            <li>type two or more characters to begin</li>
            <li>multi-word queries match all words (AND)</li>
            <li>matches are weighted: title &gt; subtitle &gt; section &gt; body</li>
            <li>use <kbd>↑</kbd> <kbd>↓</kbd> to navigate, <kbd>Enter</kbd> to open</li>
            <li>jump straight to a section by clicking its tag in a result</li>
          </ul>
        </div>`;
      return;
    }
    if (!searchIndex) return;
    const ql = q.toLowerCase();
    const scored = searchIndex
      .map(p => scorePage(p, ql))
      .filter(r => r.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 20);
    if (!scored.length) {
      list.innerHTML = `<div class='sr-hint'>no matches for <strong>${escapeHtml(q)}</strong></div>`;
      return;
    }
    scored.forEach((r, i) => {
      const item = el("a", { class: "sr-item" + (i === 0 ? " active" : ""), href: r.page.href });
      item.innerHTML = `
        <div class="sr-title">${escapeHtml(r.page.title)}</div>
        ${r.page.subtitle ? `<div class="sr-sub">${escapeHtml(r.page.subtitle)}</div>` : ""}
        ${r.snippet ? `<div class="sr-snippet">${highlight(r.snippet, q)}</div>` : ""}
        ${r.sectionHits.length ? `<div class="sr-sections">${
          r.sectionHits.slice(0, 4).map(s =>
            `<a href="${r.page.href}#${s.id}" class="sr-section">${escapeHtml(s.text)}</a>`
          ).join("")
        }</div>` : ""}
      `;
      list.appendChild(item);
    });
  }

  function buildSearchModal() {
    const modal = document.createElement("div");
    modal.id = "search-modal";
    modal.innerHTML = `
      <div class="sr-card" role="dialog" aria-label="search digger docs">
        <div class="sr-input-row">
          <svg viewBox="0 0 24 24" width="16" height="16" class="sr-icon" aria-hidden="true">
            <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" stroke-width="2"/>
            <line x1="16.5" y1="16.5" x2="22" y2="22" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </svg>
          <input type="search" class="sr-input"
                 placeholder="search collectors, detectors, frameworks, fields…"
                 autocomplete="off" spellcheck="false">
          <kbd class="sr-close-hint">esc</kbd>
        </div>
        <div class="sr-list"></div>
      </div>
    `;
    document.body.appendChild(modal);
    const input = modal.querySelector(".sr-input");
    const list = modal.querySelector(".sr-list");
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeSearch();
    });
    input.addEventListener("input", () => renderSearchResults(input.value.trim()));
    modal.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { closeSearch(); return; }
      if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Enter") {
        const items = Array.from(list.querySelectorAll(".sr-item"));
        if (!items.length) return;
        const current = list.querySelector(".sr-item.active");
        let idx = items.indexOf(current);
        if (e.key === "ArrowDown") idx = Math.min(items.length - 1, idx + 1);
        if (e.key === "ArrowUp")   idx = Math.max(0, idx - 1);
        if (e.key === "Enter") {
          if (current) { window.location.href = current.href; return; }
        } else {
          e.preventDefault();
          items.forEach(it => it.classList.remove("active"));
          items[idx].classList.add("active");
          items[idx].scrollIntoView({ block: "nearest" });
        }
      }
    });
    return modal;
  }

  async function openSearch() {
    if (!searchModal) searchModal = buildSearchModal();
    document.body.classList.add("search-open");
    const input = searchModal.querySelector(".sr-input");
    input.value = "";
    renderSearchResults("");
    setTimeout(() => input.focus(), 30);
    await buildSearchIndex();
    renderSearchResults(input.value.trim());
  }

  function closeSearch() {
    document.body.classList.remove("search-open");
  }

  // ---- keyboard shortcuts ---- //

  function bindShortcuts() {
    document.addEventListener("keydown", (e) => {
      const t = e.target;
      const typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable);
      if (typing) return;
      if (e.key === "/") {
        e.preventDefault();
        openSearch();
      } else if (e.key === "?") {
        e.preventDefault();
        showShortcuts();
      } else if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        openSearch();
      }
    });
  }

  function showShortcuts() {
    if (document.getElementById("shortcuts-modal")) {
      closeShortcuts();
      return;
    }
    const m = document.createElement("div");
    m.id = "shortcuts-modal";
    m.innerHTML = `
      <div class="sc-card">
        <h3>Keyboard shortcuts</h3>
        <table>
          <tr><td><kbd>/</kbd> or <kbd>Cmd</kbd>+<kbd>K</kbd></td><td>open search</td></tr>
          <tr><td><kbd>?</kbd></td><td>show this list</td></tr>
          <tr><td><kbd>Esc</kbd></td><td>close any overlay</td></tr>
          <tr><td><kbd>↑</kbd> <kbd>↓</kbd> <kbd>Enter</kbd></td><td>navigate search results</td></tr>
        </table>
        <button class="sc-close">close</button>
      </div>
    `;
    document.body.appendChild(m);
    m.addEventListener("click", (e) => { if (e.target === m) closeShortcuts(); });
    m.querySelector(".sc-close").addEventListener("click", closeShortcuts);
  }
  function closeShortcuts() {
    const m = document.getElementById("shortcuts-modal");
    if (m) m.remove();
  }

  // ---- boot ---- //

  document.addEventListener("DOMContentLoaded", function () {
    const active = document.body.dataset.page || "";
    injectTopbar();
    injectSidebar(active);
    injectTOC();
    injectCopyButtons();
    injectPrevNext(active);
    injectFooter();
    bindShortcuts();

    if (location.hash) {
      setTimeout(() => {
        try {
          const target = document.querySelector(location.hash);
          if (target) target.scrollIntoView({ behavior: "auto", block: "start" });
        } catch (e) { /* invalid selector */ }
      }, 50);
    }

    document.addEventListener("click", (e) => {
      if (!document.body.classList.contains("nav-open")) return;
      const inSidebar = e.target.closest && e.target.closest("#sidebar");
      const onHamburger = e.target.closest && e.target.closest(".hamburger");
      if (!inSidebar && !onHamburger) {
        document.body.classList.remove("nav-open");
      }
    });
  });

})();
