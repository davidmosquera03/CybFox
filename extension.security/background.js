// replace with verifying domain in blacklist
const blockedUrls = ["example.com", "badsite.com"];

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) {
    // Main frame only
    const url = new URL(details.url);
    if (blockedUrls.some((blocked) => url.hostname.includes(blocked))) {
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL("blocked.html"), // Redirect to warning page
      });
    }
  }
});
