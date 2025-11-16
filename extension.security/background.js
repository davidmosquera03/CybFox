// logica de ejecucion automatica tras ingresar a una pagina

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId === 0) {
    const url = new URL(details.url);
    const domain = url.hostname;
    try {
      // Step 1: Check if whitelisted
      const whitelistResponse = await fetch(
        `http://localhost:3000/api/db/check-whitelist/${encodeURIComponent(
          domain
        )}`
      );
      const whitelistData = await whitelistResponse.json();

      if (whitelistData.isWhitelisted) {
        console.log("Page is whitelisted, skipping checks");
        return; // Do nothing
      }

      // Step 2: Check if blacklisted
      const blacklistResponse = await fetch(
        `http://localhost:3000/api/db/check-blacklist/${encodeURIComponent(
          domain
        )}`
      );
      const blacklistData = await blacklistResponse.json();

      if (blacklistData.isBlacklisted) {
        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL("frontend/dist/src/blocked/blocked.html"),
        });
        return;
      }

      // Step 3: Get page info
      const pageResponse = await fetch(
        `http://localhost:3000/api/db/get-page/${encodeURIComponent(domain)}`
      );

      if (pageResponse.ok) {
        const pageData = await pageResponse.json();
        const lastScanned = pageData.page?.lastScanned;

        // Check if needs rescan (no lastScanned or > 7 days)
        if (!lastScanned || daysSince(lastScanned) > 7) {
          console.log("Scanning page with VirusTotal...");
          await fetch(
            `http://localhost:3000/api/check-vt?url=${encodeURIComponent(
              domain
            )}`
          );
        } else {
          console.log("Page scanned recently, skipping");
        }
      } else {
        // Page not in DB, scan it
        console.log("New page, scanning with VirusTotal...");
        await fetch(
          `http://localhost:3000/api/check-vt?url=${encodeURIComponent(domain)}`
        );
      }
    } catch (error) {
      console.error("Error in navigation check:", error);
    }
  }
});

// Helper function
function daysSince(date) {
  const now = new Date();
  const lastScan = new Date(date);
  const diffTime = Math.abs(now - lastScan);
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
}
