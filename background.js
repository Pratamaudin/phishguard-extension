// Store only the last committed navigation for each tab.
// Serialize writes per tab to prevent an older event overwriting a newer one.
const pendingWrites = new Map();

function queueWrite(tabId, task) {
  const previous = pendingWrites.get(tabId) || Promise.resolve();
  const next = previous.then(task).catch((error) => {
    console.error("PhishGuard: gagal memperbarui navigasi.", error);
  });
  pendingWrites.set(tabId, next);
  void next.then(() => {
    if (pendingWrites.get(tabId) === next) pendingWrites.delete(tabId);
  });
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const key = `navigation_${details.tabId}`;
  let url;
  try {
    url = new URL(details.url);
  } catch {
    queueWrite(details.tabId, () => chrome.storage.session.remove(key));
    return;
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    queueWrite(details.tabId, () => chrome.storage.session.remove(key));
    return;
  }

  const record = {
    hostname: url.hostname,
    documentId: details.documentId,
    redirectTypes: details.transitionQualifiers.filter((qualifier) =>
      ["client_redirect", "server_redirect"].includes(qualifier)
    ),
    transitionType: details.transitionType,
    timestamp: details.timeStamp
  };

  queueWrite(details.tabId, () => chrome.storage.session.set({ [key]: record }));
});

chrome.tabs.onRemoved.addListener((tabId) => {
  queueWrite(tabId, () =>
    chrome.storage.session.remove(`navigation_${tabId}`)
  );
});
