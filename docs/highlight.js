// digger docs — minimal zero-dependency syntax highlighter.
//
// Covers the languages we actually use in the docs (bash, python, yaml,
// json, plain). Each <pre> gets a small corner label and its <code> is
// re-rendered with span-wrapped tokens. CSS in style.css colors them.
//
// Auto-detects the language from content. Override per block with
// `<pre data-lang="bash">`.

(function () {

  const KEYWORDS = {
    bash: new Set([
      "if","then","else","elif","fi","for","do","done","while","case","esac",
      "function","return","export","echo","cd","ls","cat","grep","awk","sed",
      "set","unset","local","readonly","declare","alias","source","eval","exec",
      "true","false","null","trap","exit","read","printf","test",
    ]),
    python: new Set([
      "def","class","import","from","as","return","if","elif","else","try",
      "except","finally","raise","yield","for","while","in","not","and","or",
      "is","lambda","with","async","await","global","nonlocal","pass","break",
      "continue","del","True","False","None","self","cls","print","len",
    ]),
    yaml: new Set(["true","false","null","yes","no","on","off"]),
    json: new Set(["true","false","null"]),
  };

  const PROMPT_CHARS = new Set(["$", "#", ">"]);

  function detect(text) {
    const trimmed = text.trim();
    if (!trimmed) return "plain";
    // explicit hints
    if (/^\$ /m.test(trimmed)) return "bash";
    if (/^digger\s/m.test(trimmed)) return "bash";
    if (/^(pip|python|node|npm|brew|sudo|curl|cd|export)\s/m.test(trimmed)) return "bash";
    // python
    if (/^(def |class |import |from |@)/m.test(trimmed)) return "python";
    if (/^>>> /m.test(trimmed)) return "python";
    // json
    if (/^\s*\{[\s\S]*\}\s*$/.test(trimmed) && /"[^"]*"\s*:/.test(trimmed)) return "json";
    // yaml — top-level "key:" or "- " patterns common in our docs
    if (/^[a-zA-Z_][a-zA-Z0-9_]*:\s*$/m.test(trimmed) ||
        /^\s*-\s+[a-zA-Z_]/m.test(trimmed) ||
        /^id:\s/m.test(trimmed) ||
        /^controls:\s*$/m.test(trimmed)) return "yaml";
    return "plain";
  }

  // ---- per-language tokenizers ---- //
  // Each returns an array of {type, text}. Types: comment, string, number,
  // keyword, builtin, decorator, operator, punctuation, plain.

  function tokenizeBash(src) {
    const out = [];
    let i = 0;
    while (i < src.length) {
      const c = src[i];
      // line start: prompt sigil
      if ((i === 0 || src[i - 1] === "\n") && (c === "$" || c === "#")) {
        if (c === "#") {
          // comment to EOL
          let j = i;
          while (j < src.length && src[j] !== "\n") j++;
          out.push({ type: "comment", text: src.slice(i, j) });
          i = j;
          continue;
        } else if (src[i + 1] === " " || src[i + 1] === undefined) {
          out.push({ type: "prompt", text: "$" });
          i++;
          continue;
        }
      }
      if (c === "#") {
        let j = i;
        while (j < src.length && src[j] !== "\n") j++;
        out.push({ type: "comment", text: src.slice(i, j) });
        i = j;
        continue;
      }
      if (c === '"' || c === "'") {
        const quote = c;
        let j = i + 1;
        while (j < src.length && src[j] !== quote) {
          if (src[j] === "\\") j++;
          j++;
        }
        out.push({ type: "string", text: src.slice(i, Math.min(j + 1, src.length)) });
        i = Math.min(j + 1, src.length);
        continue;
      }
      // flags
      if (c === "-" && /[A-Za-z]/.test(src[i + 1] || "") && (i === 0 || /\s/.test(src[i - 1]))) {
        let j = i + 1;
        while (j < src.length && /[A-Za-z0-9-]/.test(src[j])) j++;
        out.push({ type: "operator", text: src.slice(i, j) });
        i = j;
        continue;
      }
      // variables / env
      if (c === "$" && (src[i + 1] === "{" || /[A-Za-z_]/.test(src[i + 1] || ""))) {
        let j = i + 1;
        if (src[j] === "{") {
          while (j < src.length && src[j] !== "}") j++;
          j++;
        } else {
          while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
        }
        out.push({ type: "decorator", text: src.slice(i, j) });
        i = j;
        continue;
      }
      // words
      if (/[A-Za-z_]/.test(c)) {
        let j = i;
        while (j < src.length && /[A-Za-z0-9_-]/.test(src[j])) j++;
        const word = src.slice(i, j);
        const isFirstWord = (
          i === 0 || /[\n;&|]/.test(src.slice(0, i).replace(/\s+$/, "").slice(-1))
          || /^\s*\$\s*$/.test(src.slice(Math.max(0, i - 2), i))
        );
        if (KEYWORDS.bash.has(word)) {
          out.push({ type: "keyword", text: word });
        } else if (isFirstWord) {
          out.push({ type: "builtin", text: word });
        } else {
          out.push({ type: "plain", text: word });
        }
        i = j;
        continue;
      }
      // numbers
      if (/[0-9]/.test(c)) {
        let j = i;
        while (j < src.length && /[0-9.]/.test(src[j])) j++;
        out.push({ type: "number", text: src.slice(i, j) });
        i = j;
        continue;
      }
      out.push({ type: "plain", text: c });
      i++;
    }
    return out;
  }

  function tokenizePython(src) {
    const out = [];
    let i = 0;
    while (i < src.length) {
      const c = src[i];
      // comments
      if (c === "#") {
        let j = i;
        while (j < src.length && src[j] !== "\n") j++;
        out.push({ type: "comment", text: src.slice(i, j) });
        i = j;
        continue;
      }
      // triple-quoted strings
      if ((c === '"' || c === "'") && src.slice(i, i + 3) === c.repeat(3)) {
        const quote = c.repeat(3);
        const close = src.indexOf(quote, i + 3);
        const end = close === -1 ? src.length : close + 3;
        out.push({ type: "string", text: src.slice(i, end) });
        i = end;
        continue;
      }
      // single/double quoted strings (with f/r/b prefixes)
      const strMatch = src.slice(i).match(/^[rfbRFB]{0,2}(['"])/);
      if (strMatch) {
        const quote = strMatch[1];
        const prefixLen = strMatch[0].length - 1;
        let j = i + prefixLen + 1;
        while (j < src.length && src[j] !== quote) {
          if (src[j] === "\\") j++;
          j++;
        }
        out.push({ type: "string", text: src.slice(i, Math.min(j + 1, src.length)) });
        i = Math.min(j + 1, src.length);
        continue;
      }
      // decorators
      if (c === "@" && /[A-Za-z_]/.test(src[i + 1] || "")) {
        let j = i + 1;
        while (j < src.length && /[A-Za-z0-9_.]/.test(src[j])) j++;
        out.push({ type: "decorator", text: src.slice(i, j) });
        i = j;
        continue;
      }
      // words
      if (/[A-Za-z_]/.test(c)) {
        let j = i;
        while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
        const word = src.slice(i, j);
        if (KEYWORDS.python.has(word)) {
          out.push({ type: "keyword", text: word });
        } else if (src[j] === "(") {
          out.push({ type: "builtin", text: word });
        } else {
          out.push({ type: "plain", text: word });
        }
        i = j;
        continue;
      }
      // numbers
      if (/[0-9]/.test(c)) {
        let j = i;
        while (j < src.length && /[0-9._a-fA-Fx]/.test(src[j])) j++;
        out.push({ type: "number", text: src.slice(i, j) });
        i = j;
        continue;
      }
      out.push({ type: "plain", text: c });
      i++;
    }
    return out;
  }

  function tokenizeYaml(src) {
    const out = [];
    const lines = src.split("\n");
    lines.forEach((line, idx) => {
      // comment
      const ci = line.indexOf("#");
      const codePart = ci === -1 ? line : line.slice(0, ci);
      const commentPart = ci === -1 ? "" : line.slice(ci);
      // key: value
      const keyMatch = codePart.match(/^(\s*-?\s*)([A-Za-z_][A-Za-z0-9_./-]*)(:)(\s*)(.*)$/);
      if (keyMatch) {
        const [, indent, key, colon, ws, value] = keyMatch;
        if (indent) out.push({ type: "plain", text: indent });
        out.push({ type: "keyword", text: key });
        out.push({ type: "punctuation", text: colon });
        if (ws) out.push({ type: "plain", text: ws });
        if (value) {
          if (/^["']/.test(value)) {
            out.push({ type: "string", text: value });
          } else if (KEYWORDS.yaml.has(value.trim().toLowerCase())) {
            out.push({ type: "number", text: value });
          } else if (/^-?\d+(\.\d+)?$/.test(value.trim())) {
            out.push({ type: "number", text: value });
          } else {
            out.push({ type: "plain", text: value });
          }
        }
      } else {
        // dash list, plain text
        out.push({ type: "plain", text: codePart });
      }
      if (commentPart) out.push({ type: "comment", text: commentPart });
      if (idx < lines.length - 1) out.push({ type: "plain", text: "\n" });
    });
    return out;
  }

  function tokenizeJson(src) {
    const out = [];
    let i = 0;
    while (i < src.length) {
      const c = src[i];
      if (c === '"') {
        let j = i + 1;
        while (j < src.length && src[j] !== '"') {
          if (src[j] === "\\") j++;
          j++;
        }
        const text = src.slice(i, Math.min(j + 1, src.length));
        // key vs string by looking ahead for ':'
        let k = Math.min(j + 1, src.length);
        while (k < src.length && /\s/.test(src[k])) k++;
        const isKey = src[k] === ":";
        out.push({ type: isKey ? "keyword" : "string", text });
        i = Math.min(j + 1, src.length);
        continue;
      }
      if (/[0-9-]/.test(c)) {
        let j = i;
        while (j < src.length && /[0-9.eE+-]/.test(src[j])) j++;
        out.push({ type: "number", text: src.slice(i, j) });
        i = j;
        continue;
      }
      if (/[A-Za-z_]/.test(c)) {
        let j = i;
        while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
        const word = src.slice(i, j);
        if (KEYWORDS.json.has(word)) {
          out.push({ type: "number", text: word });
        } else {
          out.push({ type: "plain", text: word });
        }
        i = j;
        continue;
      }
      if ("{}[],:".includes(c)) {
        out.push({ type: "punctuation", text: c });
        i++;
        continue;
      }
      out.push({ type: "plain", text: c });
      i++;
    }
    return out;
  }

  const TOKENIZERS = {
    bash: tokenizeBash,
    python: tokenizePython,
    yaml: tokenizeYaml,
    json: tokenizeJson,
  };

  function escapeHtml(s) {
    return (s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function render(tokens) {
    return tokens.map(t => {
      const text = escapeHtml(t.text);
      if (t.type === "plain") return text;
      return `<span class="tok-${t.type}">${text}</span>`;
    }).join("");
  }

  function highlightBlock(pre) {
    const code = pre.querySelector("code");
    if (!code || code.dataset.highlighted) return;
    const explicit = pre.dataset.lang || code.dataset.lang
      || (Array.from(code.classList).find(c => c.startsWith("lang-")) || "").replace("lang-", "");
    const lang = explicit || detect(code.textContent);
    if (lang === "plain") {
      code.dataset.highlighted = "1";
      tagPre(pre, "text");
      return;
    }
    const tok = TOKENIZERS[lang];
    if (!tok) return;
    try {
      const tokens = tok(code.textContent);
      code.innerHTML = render(tokens);
      code.dataset.highlighted = "1";
      tagPre(pre, lang);
    } catch (e) {
      // any tokenizer bug: leave the block untouched
      console.warn("highlight failed", e);
    }
  }

  function tagPre(pre, lang) {
    const tag = document.createElement("span");
    tag.className = "pre-lang";
    tag.textContent = lang;
    pre.appendChild(tag);
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("main pre").forEach(highlightBlock);
  });

})();
