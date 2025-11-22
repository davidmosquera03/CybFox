// ============= Helpers =============

// Limpia URLs largas para mandarlas a VirusTotal
function cleanUrlForVT(raw) {
  try {
    const u = new URL(raw);

    // No escaneamos cosas del propio navegador ni Google Search
    const blockedHosts = ["www.google.com", "google.com"];
    if (blockedHosts.includes(u.hostname)) return null;
    if (raw.startsWith("chrome://") || raw.startsWith("edge://")) return null;

    // Quitamos query y fragmentos para evitar canonicalization error
    return `${u.origin}${u.pathname}`;
  } catch {
    return null;
  }
}

function daysSince(date) {
  if (!date) return Infinity;
  const now = new Date();
  const old = new Date(date);
  return Math.ceil((now - old) / (1000 * 60 * 60 * 24));
}

// Permisos temporales cuando el usuario pulsa "Acceder bajo tu propio riesgo"
const tempAllowed = new Set();

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "ALLOW_TEMP" && msg.url) {
    tempAllowed.add(msg.url);
    console.log("[CybFox] Override temporal para:", msg.url);
    sendResponse?.({ ok: true });
  }
});

// ============= Lógica principal =============

const RISK_THRESHOLD = 60; // finalRisk >= 60 → bloqueamos

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Solo frame principal
  if (details.frameId !== 0) return;

  const rawUrl = details.url;
  if (!rawUrl || !rawUrl.startsWith("http")) return;

  (async () => {
    try {
      const urlObj = new URL(rawUrl);
      const domain = urlObj.hostname;
      const encodedDomain = encodeURIComponent(domain);
      const encodedFullUrl = encodeURIComponent(rawUrl);

      // 1) WHITELIST
      let isWhitelisted = false;
      try {
        const wlRes = await fetch(
          `http://localhost:3000/api/db/check-whitelist/${encodedDomain}`
        );
        if (wlRes.ok) {
          const wl = await wlRes.json();
          isWhitelisted = !!wl.isWhitelisted;
        }
      } catch (e) {
        console.warn("[CybFox] Error consultando whitelist:", e);
      }

      if (isWhitelisted) {
        console.log("[CybFox] Dominio en whitelist, se omite análisis:", domain);
        return;
      }

      // 2) BLACKLIST
      let isBlacklisted = false;
      try {
        const blRes = await fetch(
          `http://localhost:3000/api/db/check-blacklist/${encodedDomain}`
        );
        if (blRes.ok) {
          const bl = await blRes.json();
          isBlacklisted = !!bl.isBlacklisted;
        }
      } catch (e) {
        console.warn("[CybFox] Error consultando blacklist:", e);
      }

      // 3) Traer info existente desde la BD (🔴 IMPORTANTE: por dominio, no por URL completa)
      let page = null;
      let needScan = true;

      try {
        const dbRes = await fetch(
          `http://localhost:3000/api/db/get-page/${domain}`
        );
        if (dbRes.ok) {
          const dbJson = await dbRes.json();
          page = dbJson.page || null;

          if (page?.lastScanned && daysSince(page.lastScanned) <= 7) {
            needScan = false; // escaneado hace ≤ 7 días
          }
        }
      } catch (e) {
        console.warn("[CybFox] Error consultando get-page inicial:", e);
      }

      // 4) Si hace falta, escaneamos con VT/CRT y refrescamos página en BD
      if (needScan) {
        console.log("[CybFox] Escaneando página (VT / CRT):", rawUrl);

        const vtClean = cleanUrlForVT(rawUrl);

        const tasks = [];

        if (vtClean) {
          tasks.push(
            fetch(
              `http://localhost:3000/api/check-vt?url=${encodeURIComponent(
                vtClean
              )}`
            )
              .then((r) => r.json())
              .catch((e) => console.warn("[CybFox] Error check-vt:", e))
          );
        }

        tasks.push(
          fetch(
            `http://localhost:3000/api/check-crt?domain=${encodedDomain}`
          )
            .then((r) => r.json())
            .catch((e) => console.warn("[CybFox] Error check-crt:", e))
        );

        await Promise.all(tasks).catch((e) =>
          console.warn("[CybFox] Error en tareas de escaneo:", e)
        );

        // Volvemos a consultar la BD para tener currentScore + reports actualizados
        try {
          const dbRef = await fetch(
            `http://localhost:3000/api/db/get-page/${domain}`
          );
          if (dbRef.ok) {
            const dbJson = await dbRef.json();
            page = dbJson.page || null;
          }
        } catch (e) {
          console.warn("[CybFox] Error recargando get-page:", e);
        }
      }

      // 5) Extraer VT, CRT, currentScore de page.reports
      let vtStats = {
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0
      };

      let crtInfo = { https: false };
      let meta = { lastScanned: null, currentScore: null };

      if (page) {
        meta.lastScanned = page.lastScanned || null;
        if (typeof page.currentScore === "number") {
          meta.currentScore = page.currentScore;
        }

        if (Array.isArray(page.reports)) {
          for (const rep of page.reports) {
            if (rep.source === "VirusTotal" && rep.data) {
              vtStats = {
                malicious: Number(rep.data.malicious || 0),
                suspicious: Number(rep.data.suspicious || 0),
                harmless: Number(rep.data.harmless || 0),
                undetected: Number(rep.data.undetected || 0)
              };
            }
            if (rep.source === "CRT" && rep.data) {
              crtInfo.https = !!rep.data.https;
            }
          }
        }
      }

      // Guardamos en storage para que blocked.html lo lea sin más fetch
      chrome.storage.local.set({
        [`vt:${domain}`]: vtStats,
        [`crt:${domain}`]: crtInfo,
        [`meta:${domain}`]: meta
      });

      // 6) Cálculo del RIESGO

      // VirusTotal → % de engines que lo marcan malicioso
      const totalVT =
        vtStats.malicious +
        vtStats.suspicious +
        vtStats.harmless +
        vtStats.undetected;

      let vtRisk = 0;
      if (totalVT > 0) {
        vtRisk = (vtStats.malicious * 100) / totalVT;
      }

      // currentScore: 0 = pésimo, 100 = muy confiable
      // finalRisk: 0 = confiable, 100 = muy peligroso
      let finalRisk = vtRisk;
      if (typeof meta.currentScore === "number") {
        const safeScore = Math.max(0, Math.min(100, meta.currentScore));
        finalRisk = 100 - safeScore;
      }

      console.log(
        "[CybFox] domain",
        domain,
        "isBlacklisted:",
        isBlacklisted,
        "currentScore:",
        meta.currentScore,
        "vtStats:",
        vtStats,
        "finalRisk:",
        finalRisk
      );

      // 7) DECISIÓN DE BLOQUEO

      // a) Si está en blacklist → SIEMPRE bloqueamos (no hay override)
      if (isBlacklisted) {
        console.log("[CybFox] Blacklist → bloqueo forzado:", rawUrl);
        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL(`blocked.html?url=${encodedFullUrl}`)
        });
        return;
      }

      // b) No está en blacklist → aplicamos umbral de riesgo
      if (finalRisk >= RISK_THRESHOLD) {
        // ¿El usuario ya aceptó "bajo tu propio riesgo" para ESTA URL?
        if (tempAllowed.has(rawUrl)) {
          console.log(
            "[CybFox] Riesgo alto, pero usuario aceptó override para:",
            rawUrl
          );
          tempAllowed.delete(rawUrl); // solo para esta navegación
          return; // dejamos pasar
        }

        console.log(
          "[CybFox] Bloqueando navegación a",
          rawUrl,
          "(risk:",
          finalRisk,
          ")"
        );

        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL(`blocked.html?url=${encodedFullUrl}`)
        });
        return;
      }

      // c) Riesgo bajo → no bloqueamos
      console.log("[CybFox] Riesgo bajo, navegación permitida:", rawUrl);
    } catch (err) {
      console.error("[CybFox] Error en onBeforeNavigate:", err);
    }
  })();
});
