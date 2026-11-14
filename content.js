// Native getters remain reliable when form controls are named action/method.
const nativeFormAction = Object.getOwnPropertyDescriptor(
  HTMLFormElement.prototype, "action"
).get;
const nativeFormMethod = Object.getOwnPropertyDescriptor(
  HTMLFormElement.prototype, "method"
).get;

function detectDomainRisks(hostname) {
  const findings = [];
  const host = hostname.toLowerCase().replace(/\.$/, "");

  // Daftar awal domain pembanding.
  const protectedBrands = [
    { name: "Google", token: "google", domain: "google.com" },
    { name: "PayPal", token: "paypal", domain: "paypal.com" },
    { name: "Microsoft", token: "microsoft", domain: "microsoft.com" }
  ];

  // Menyamakan beberapa angka yang menyerupai huruf.
  function normalizeToken(token) {
    const replacements = {
      "0": "o",
      "1": "l",
      "3": "e",
      "5": "s",
      "7": "t"
    };

    return token.replace(/[01357]/g, (char) => replacements[char]);
  }

  const tokens = host.split(/[.-]/).map(normalizeToken);

  for (const brand of protectedBrands) {
    const belongsToDomain =
      host === brand.domain ||
      host.endsWith("." + brand.domain);

    if (belongsToDomain) {
      continue;
    }

    if (tokens.includes(brand.token)) {
      findings.push(
        `Hostname mengandung pola nama ${brand.name}, ` +
        `tetapi berada di luar ${brand.domain}. Periksa alamatnya.`
      );
    }
  }

  return findings;
}
// Only compare full URL/hostname labels, not labels such as "Login".
function parseLinkLabel(text) {
  const label = text.trim();
  if (!label || label.length > 2048 || /\s/.test(label)) return null;

  const hasScheme = /^https?:\/\//i.test(label);
  const looksLikeHostname = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?(?:[/?#][^\s]*)?$/i.test(label);
  if (!hasScheme && !looksLikeHostname) return null;

  try {
    const url = new URL(hasScheme ? label : "https://" + label);
    if (!["http:", "https:"].includes(url.protocol) || !url.hostname) return null;
    return url;
  } catch {
    return null;
  }
}

function normalizeHostname(hostname) {
  return hostname.toLowerCase().replace(/\.$/, "");
}

function detectLinkRisks() {
  const findings = new Set();
  for (const anchor of document.querySelectorAll("a[href]")) {
    // Do not describe hidden link text as visible text.
    if (anchor.getClientRects().length === 0) continue;
    const labelURL = parseLinkLabel(anchor.innerText);
    if (!labelURL) continue;

    try {
      const destination = new URL(anchor.href, document.baseURI);
      if (!["http:", "https:"].includes(destination.protocol)) continue;
      const shownHost = normalizeHostname(labelURL.hostname);
      const actualHost = normalizeHostname(destination.hostname);
      if (shownHost !== actualHost) {
        findings.add(
          `Teks tautan menyebut ${shownHost}, tetapi tujuan pada HTML memakai ${actualHost}.`
        );
      }
    } catch {
      // Invalid/non-HTTP destinations are outside this particular rule.
    }
  }
  return [...findings];
}

function scanPage() {
  const findings = [
    ...detectDomainRisks(window.location.hostname),
    ...detectLinkRisks()
  ];

  // Mencari elemen password tanpa membaca isinya.
  const passwordFields = document.querySelectorAll('input[type="password"]');

  if (passwordFields.length > 0 && window.location.protocol === "http:") {
    findings.push("Halaman memiliki kolom password tetapi menggunakan HTTP.");
  }

  // Set mencegah satu formulir diperiksa berulang kali.
  const forms = new Set();

  for (const field of passwordFields) {
    if (field.form) {
      forms.add(field.form);
    }
  }

  // Mengumpulkan tombol yang dapat mengirim formulir.
  const submitControls = [
    ...document.querySelectorAll("button, input")
  ].filter((control) => {
    return (
      control.type === "submit" ||
      (control instanceof HTMLInputElement &&
        control.type === "image")
    );
  });

  for (const form of forms) {
    const formAction = nativeFormAction.call(form);
    const formMethod = nativeFormMethod.call(form);

    // Tujuan utama formulir.
    const destinations = [
      {
        action: formAction,
        method: formMethod
      }
    ];

    // Tujuan yang digunakan ketika masing-masing tombol ditekan.
    for (const control of submitControls) {
      if (control.form !== form) {
        continue;
      }

      destinations.push({
        action: control.hasAttribute("formaction")
          ? control.formAction
          : formAction,

        method: control.hasAttribute("formmethod")
          ? control.formMethod
          : formMethod
      });
    }

    for (const target of destinations) {
      // Metode dialog tidak mengirim formulir ke server.
      if (target.method.toLowerCase() === "dialog") {
        continue;
      }

      try {
        const destination = new URL(
          target.action,
          document.baseURI
        );

        if (destination.hostname !== window.location.hostname) {
          findings.push(
            `Tujuan formulir pada HTML memakai hostname berbeda: ${destination.hostname}`
          );
        }

        if (destination.protocol === "http:") {
          findings.push(
            "Tujuan formulir pada HTML menggunakan HTTP."
          );
        }
      } catch {
        findings.push(
          "Alamat tujuan formulir password tidak dapat dianalisis."
        );
      }
    }
  }

  // Menghapus temuan dengan teks yang sama.
  const uniqueFindings = [...new Set(findings)];

  return {
    hostname: window.location.hostname,
    passwordFieldCount: passwordFields.length,
    status:
      uniqueFindings.length > 0
        ? "Ada indikator risiko"
        : "Tidak ditemukan indikator dari pemeriksaan awal",
    findings: uniqueFindings,
  };
}

// Menerima permintaan pemeriksaan dari popup ekstensi.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "SCAN_PAGE") {
    try {
      sendResponse(scanPage());
    } catch (error) {
      console.error("PhishGuard: pemeriksaan halaman gagal.", error);
      sendResponse({ error: "SCAN_FAILED" });
    }
  }
});
function renderWarning(result) {

  // Tidak menampilkan banner jika tidak ada temuan.
  if (result.findings.length === 0) {
    return;
  }

  const host = document.createElement("div");

  host.style.cssText = `
    position: fixed !important;
    bottom: 20px !important;
    right: 20px !important;
    width: min(360px, calc(100vw - 40px)) !important;
    z-index: 2147483647 !important;
  `;

  // Memisahkan tampilan banner dari CSS halaman.
  const shadow = host.attachShadow({ mode: "closed" });

  const style = document.createElement("style");
  style.textContent = `
    .warning {
      padding: 18px;
      border: 2px solid #fbbf24;
      border-radius: 12px;
      background: #0f172a;
      color: #f8fafc;
      font: 14px/1.5 Arial, sans-serif;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
      overflow-wrap: anywhere;
      max-height: 60vh;
      overflow-y: auto;
    }

    h2 {
      margin: 0 0 10px;
      color: #fbbf24;
      font-size: 18px;
    }

    ul {
      margin: 10px 0;
      padding-left: 20px;
    }

    li + li {
      margin-top: 8px;
    }

    p {
      margin: 12px 0;
    }

    button {
      padding: 8px 12px;
      border: 1px solid #94a3b8;
      border-radius: 6px;
      background: #334155;
      color: #ffffff;
      cursor: pointer;
    }

    button:focus-visible {
      outline: 2px solid #fbbf24;
      outline-offset: 3px;
    }
  `;

  const banner = document.createElement("section");
  banner.className = "warning";
  banner.setAttribute("role", "status");

  const title = document.createElement("h2");
  title.textContent = "PhishGuard: ada indikator risiko";

  const list = document.createElement("ul");

  for (const finding of result.findings) {
    const item = document.createElement("li");
    item.textContent = finding;
    list.appendChild(item);
  }

  const note = document.createElement("p");
  note.textContent =
    "Temuan ini bukan kepastian phishing. " +
    "Periksa alamat, tujuan tautan, dan formulir sebelum memasukkan data.";

  const closeButton = document.createElement("button");
  closeButton.type = "button";
  closeButton.textContent = "Tutup peringatan";
  closeButton.addEventListener("click", () => {
    host.remove();
    if (currentBanner === host) currentBanner = null;
  });

  banner.append(title, list, note, closeButton);
  shadow.append(style, banner);

  (document.body || document.documentElement).appendChild(host);

  return host;
}

// Pemeriksaan awal saat content script dijalankan.
let currentBanner = null;
let previousFindings = "";
let scanTimer = null;

function refreshWarning() {
  let result;
  try {
    result = scanPage();
  } catch (error) {
    currentBanner?.remove();
    currentBanner = null;
    previousFindings = "";
    console.error("PhishGuard: pemeriksaan otomatis gagal.", error);
    return;
  }
  const signature = JSON.stringify([...result.findings].sort());

  // Temuan sama: tidak membuat banner baru.
  // Ini juga menghormati banner yang sudah ditutup pengguna.
  if (signature === previousFindings) {
    return;
  }

  previousFindings = signature;

  if (currentBanner) {
    currentBanner.remove();
    currentBanner = null;
  }

  if (result.findings.length > 0) {
    currentBanner = renderWarning(result);
  }
}

function containsRelevantElement(node) {
  if (!(node instanceof Element)) {
    return false;
  }

  return (
    node.matches("form, input, button, base, a[href]") ||
    node.querySelector("form, input, button, base, a[href]") !== null
  );
}

const pageObserver = new MutationObserver((mutations) => {
  const needsScan = mutations.some((mutation) => {
    if (mutation.type === "attributes") {
      return true;
    }
    if (mutation.type === "characterData") {
      return Boolean(mutation.target.parentElement?.closest("a[href]"));
    }
    // Replacing a link's textContent reports childList on the anchor.
    if (mutation.target instanceof Element &&
        mutation.target.closest("a[href]")) {
      return true;
    }

    return [
      ...mutation.addedNodes,
      ...mutation.removedNodes
    ].some(containsRelevantElement);
  });

  // Menggabungkan perubahan berdekatan menjadi satu pemeriksaan.
  if (!needsScan || scanTimer !== null) {
    return;
  }

  scanTimer = setTimeout(() => {
    scanTimer = null;
    refreshWarning();
  }, 300);
});

pageObserver.observe(document.documentElement, {
  childList: true,
  characterData: true,
  subtree: true,
  attributes: true,
  attributeFilter: [
    "action",
    "method",
    "formaction",
    "formmethod",
    "type",
    "form",
    "id",
    "href"
  ]
});

// Pemeriksaan pertama.
refreshWarning();