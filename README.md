# PhishGuard

A Chrome extension that identifies selected phishing indicators and explains its findings.

Built with JavaScript and Chrome Manifest V3 as a cybersecurity learning and portfolio project.

> PhishGuard uses heuristic rules. Findings require interpretation, and a result without findings does not guarantee that a website is safe.

## Features

- Detects selected brand-name patterns outside configured reference domains.
- Identifies password fields on HTTP pages.
- Checks HTML form destinations for HTTP and hostname differences.
- Checks alternative submission destinations defined by `formaction`.
- Accounts for submission methods defined by `formmethod`.
- Compares URL-like link text with its HTML destination hostname.
- Monitors relevant DOM changes to update warnings dynamically.
- Displays findings in a popup and an on-page warning banner.
- Shows the number of detected password fields.
- Displays client-side and server-side redirect markers reported by Chrome.

## Installation

1. Download this repository using **Code → Download ZIP**.
2. Extract the ZIP.
3. Open `chrome://extensions` in Chrome.
4. Enable **Developer mode**.
5. Click **Load unpacked**.
6. Select the folder containing `manifest.json`.
7. Open or refresh an HTTP/HTTPS page.
8. Open PhishGuard and click **Periksa halaman**.

After updating the extension files, reload the extension and refresh the page being tested.

## Project Files

| File | Purpose |
|---|---|
| `manifest.json` | Extension configuration and permissions |
| `content.js` | Page analysis, DOM monitoring, and warning banner |
| `background.js` | Navigation events and per-document redirect metadata |
| `popup.html` | Popup interface |
| `popup.js` | Scan requests, result validation, and display |
| `test.html` | Form and submit-button testing |
| `redirect-test.html` | Client-side redirect testing |
| `link-test.html` | Link mismatch and dynamic text testing |
| `redirect_server.py` | Local HTTP server for server-side redirect testing |

## How It Works

The content script examines the main page DOM and returns findings to the popup.

A MutationObserver schedules another scan when relevant elements, attributes, or link text change. The banner updates when the findings change.

The background service worker receives Chrome navigation events. It stores the latest committed navigation metadata for each tab in `chrome.storage.session`. The popup checks the document identity before displaying that metadata.

Redirect information is displayed separately from risk findings. A redirect alone is not evidence of phishing.

## Local Testing

### Forms and Links

Open the HTML test pages using VS Code Live Server.

- `test.html`: inspect password fields and HTML submission destinations.
- `link-test.html`: compare matching and mismatching link labels, then change link text using the test button.
- `redirect-test.html`: wait for the meta refresh to navigate to `test.html`.

Do not enter real credentials. Link mismatch detection does not require clicking the links.

### Server-Side Redirect

Run the local server:

```powershell
python redirect_server.py
```

Open the address printed in the terminal. With port `8765`, use:

```text
http://127.0.0.1:8765/redirect
```

After the redirect completes, open PhishGuard and run a scan without refreshing the destination page.

Expected navigation information: a server-side redirect reported by Chrome.

Press **Ctrl+C** in the terminal to stop the server.

## Manual Validation

The following behaviors were observed during development:

| Scenario | Observed result |
|---|---|
| Password field on an HTTP page | HTTP finding displayed |
| Form destination on another hostname | Hostname difference displayed |
| Alternative destination on a submit button | Alternative hostname detected |
| Form inserted after page load | Warning updated automatically |
| Client-side meta refresh | Client redirect information displayed |
| HTTP 302 redirect | Server redirect information displayed |
| Juice Shop login on localhost | Password field and HTTP findings displayed |
| URL label differs from link destination | Link mismatch displayed |
| Link text changed dynamically | Warning updated without a refresh |

These are functional checks, not a measurement of detection accuracy across real phishing websites.

## Privacy and Permissions

The implementation does not read, store, or transmit username or password values.

- `webNavigation` receives navigation metadata.
- `storage` stores temporary navigation records.
- Content scripts run on matching HTTP/HTTPS pages to inspect page structure.

Stored navigation records contain the final hostname, document identifier, redirect markers, navigation type, and timestamp. They do not contain full URLs or form values.

There is no external reputation API integration.

## Limitations

- Domain matching covers a small configured set of patterns.
- Heuristics can produce false positives and false negatives.
- Some file-like link labels may be mistaken for hostnames, depending on the parser version.
- Different hostnames can be legitimate, including authentication providers and tracking links.
- HTML form destinations do not necessarily represent requests made by JavaScript.
- Iframes and page Shadow DOM are not inspected.
- Full redirect chains and intermediate URLs are not recorded.
- JavaScript can change link behavior at click time.
- Phishing pages using HTTPS and same-host submissions may produce no findings.
- The on-page banner is informational and does not block navigation or submission.

## Development Lessons

This project demonstrates:

- Chrome extension messaging and Manifest V3 service workers.
- DOM inspection and MutationObserver.
- URL parsing and hostname comparisons.
- Defensive handling of named form controls.
- Result validation, timeouts, and error states.
- The importance of testing false positives alongside successful detections.
