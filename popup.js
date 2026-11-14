const scanButton = document.getElementById("scanButton");
const hostnameElement = document.getElementById("hostname");
const statusElement = document.getElementById("status");
const findingsElement = document.getElementById("findings");
const passwordCountElement = document.getElementById("passwordCount");
const navigationElement = document.getElementById("navigationInfo");

function scanError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

async function withTimeout(promise, milliseconds = 6000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(scanError("TIMEOUT")), milliseconds);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function validResult(result) {
  return result && Number.isInteger(result.passwordFieldCount) &&
    result.passwordFieldCount >= 0 && typeof result.hostname === "string" &&
    typeof result.status === "string" && Array.isArray(result.findings) &&
    result.findings.every((item) => typeof item === "string");
}

async function showNavigationInfo(tabId, hostname, documentId) {
  try {
    const key = `navigation_${tabId}`;
    const data = await withTimeout(chrome.storage.session.get(key));
    const record = data[key];
    if (!record || record.hostname !== hostname ||
        !documentId || record.documentId !== documentId) {
      navigationElement.textContent =
        "Catatan navigasi untuk dokumen ini belum tersedia.";
      return;
    }
    if (!Array.isArray(record.redirectTypes)) {
      throw new Error("Catatan navigasi tidak valid.");
    }
    const descriptions = [];
    if (record.redirectTypes.includes("client_redirect")) {
      descriptions.push("Pengalihan sisi halaman (JavaScript atau meta refresh)");
    }
    if (record.redirectTypes.includes("server_redirect")) {
      descriptions.push("Pengalihan sisi server melalui header HTTP");
    }
    navigationElement.textContent = descriptions.length > 0
      ? descriptions.join(". ") + ". Redirect sendiri bukan bukti phishing."
      : "Chrome tidak melaporkan penanda redirect pada navigasi terakhir yang tercatat.";
  } catch (error) {
    navigationElement.textContent = "Informasi navigasi gagal dibaca.";
    console.error("PhishGuard: gagal membaca navigasi.", error);
  }
}

async function scanCurrentPage() {
  scanButton.disabled = true;
  let phase = "tab";
  try {
    passwordCountElement.textContent = "Kolom password terdeteksi: memeriksa...";
    hostnameElement.textContent = "Memeriksa...";
    statusElement.textContent = "Pemeriksaan sedang berjalan...";
    statusElement.removeAttribute("data-state");
    findingsElement.replaceChildren();
    navigationElement.textContent = "Menunggu hasil pemeriksaan...";

    const [tab] = await withTimeout(chrome.tabs.query({
      active: true, currentWindow: true
    }));
    if (!tab || typeof tab.id !== "number") throw scanError("NO_TAB");

    phase = "frame";
    const frame = await withTimeout(chrome.webNavigation.getFrame({
      tabId: tab.id, frameId: 0
    }));
    if (!frame || !/^https?:\/\//i.test(frame.url)) {
      throw scanError("UNSUPPORTED_PAGE");
    }
    if (!frame.documentId) throw scanError("NO_DOCUMENT");

    phase = "message";
    // Address the exact document, rather than whichever page loads next.
    const result = await withTimeout(chrome.tabs.sendMessage(
      tab.id, { type: "SCAN_PAGE" }, { documentId: frame.documentId }
    ));
    if (result?.error === "SCAN_FAILED") throw scanError("SCAN_FAILED");
    if (!validResult(result)) throw scanError("INVALID_RESULT");

    phase = "verify";
    const currentFrame = await withTimeout(chrome.webNavigation.getFrame({
      tabId: tab.id, frameId: 0
    }));
    if (currentFrame?.documentId !== frame.documentId ||
        new URL(currentFrame.url).hostname !== result.hostname) {
      throw scanError("PAGE_CHANGED");
    }

    hostnameElement.textContent = result.hostname;
    passwordCountElement.textContent =
      `Kolom password terdeteksi: ${result.passwordFieldCount}`;
    statusElement.textContent = result.status;
    statusElement.dataset.state = result.findings.length > 0 ? "warning" : "neutral";
    for (const finding of result.findings) {
      const item = document.createElement("li");
      item.textContent = finding;
      findingsElement.appendChild(item);
    }
    phase = "navigation";
    await showNavigationInfo(tab.id, result.hostname, frame.documentId);
  } catch (error) {
    const messages = {
      NO_TAB: "Tab aktif tidak ditemukan.",
      UNSUPPORTED_PAGE: "Halaman ini tidak didukung. Buka halaman HTTP atau HTTPS biasa.",
      NO_DOCUMENT: "Identitas dokumen belum tersedia. Tunggu halaman dimuat, lalu coba lagi.",
      SCAN_FAILED: "Pemeriksa halaman mengalami error. Lihat Console halaman untuk detail.",
      INVALID_RESULT: "Format hasil pemeriksaan tidak sesuai. Reload ekstensi, lalu refresh halaman.",
      PAGE_CHANGED: "Halaman berpindah saat diperiksa. Periksa kembali halaman tujuan.",
      TIMEOUT: "Pemeriksaan melewati batas waktu. Tunggu halaman selesai dimuat, lalu coba lagi."
    };
    hostnameElement.textContent = "Tidak tersedia";
    passwordCountElement.textContent = "Kolom password terdeteksi: tidak tersedia";
    findingsElement.replaceChildren();
    statusElement.textContent = messages[error.code] || (
      phase === "message"
        ? "Tidak dapat menghubungi pemeriksa halaman. Refresh halaman dan periksa izin akses situs ekstensi."
        : "Pemeriksaan gagal. Lihat Console popup untuk detail."
    );
    statusElement.dataset.state = "error";
    navigationElement.textContent =
      "Informasi navigasi tidak ditampilkan karena pemeriksaan gagal.";
    console.error(`PhishGuard: pemeriksaan gagal pada tahap ${phase}.`, error);
  } finally {
    scanButton.disabled = false;
  }
}

if ([scanButton, hostnameElement, statusElement, findingsElement,
     passwordCountElement, navigationElement].every(Boolean)) {
  scanButton.addEventListener("click", scanCurrentPage);
} else {
  console.error("PhishGuard: elemen popup tidak lengkap; periksa ID pada popup.html.");
  if (statusElement) {
    statusElement.textContent = "Tampilan popup tidak lengkap. Periksa popup.html.";
    statusElement.dataset.state = "error";
  }
  if (scanButton) scanButton.disabled = true;
}
