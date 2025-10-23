chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId === 0) {
    const url = new URL(details.url);
    const domain = url.hostname;

    try {
      const response = await fetch(
        `http://localhost:3000/api/check-blacklist/${encodeURIComponent(
          domain
        )}`
      );
      const data = await response.json();

      if (data.isBlacklisted) {
        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL("blocked.html"),
        });
      }
    } catch (error) {
      console.error("Error checking blacklist:", error);
    }
  }
});
