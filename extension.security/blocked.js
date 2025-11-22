// blocked.js — UI de página bloqueada (usa currentScore + VT + SSL + override)

(() => {
  try {
    const params = new URLSearchParams(window.location.search);
    const encodedUrl = params.get("url") || "";
    const fullUrl = encodedUrl ? decodeURIComponent(encodedUrl) : "";

    const urlSpan = document.getElementById("url-text");
    const domainSpan = document.getElementById("domain-text");

    if (urlSpan) {
      urlSpan.textContent = fullUrl || "URL no disponible";
    }

    let domain = "Este sitio";
    if (fullUrl) {
      try {
        domain = new URL(fullUrl).hostname;
      } catch {
        // si falla el new URL, dejamos "Este sitio"
      }
    }
    if (domainSpan) domainSpan.textContent = domain;

    // ====== Cargar datos guardados por background ======
    chrome.storage.local.get(
      [`vt:${domain}`, `crt:${domain}`, `meta:${domain}`],
      (raw) => {
        try {
          const vtEntry = raw[`vt:${domain}`] || {};
          const crt = raw[`crt:${domain}`] || { https: false };
          const meta = raw[`meta:${domain}`] || {};

          // vtEntry puede venir como { malicious, suspicious, harmless, undetected }
          const stats = {
            malicious: Number(vtEntry.malicious || 0),
            suspicious: Number(vtEntry.suspicious || 0),
            harmless: Number(vtEntry.harmless || 0),
            undetected: Number(vtEntry.undetected || 0)
          };

          const total =
            stats.malicious +
            stats.suspicious +
            stats.harmless +
            stats.undetected;

          // riesgo con VT (backup)
          const riskyVT = stats.malicious * 2 + stats.suspicious;
          const vtRisk = total > 0 ? (riskyVT * 100) / total : 0;

          // currentScore: 0 = muy malo, 100 = muy bueno (desde la BD)
          const cybScore =
            typeof meta.currentScore === "number" ? meta.currentScore : null;

          // finalRisk: 0 = confiable, 100 = muy riesgoso
          let finalRisk = vtRisk;
          if (cybScore != null) {
            const safeScore = Math.max(0, Math.min(100, cybScore));
            finalRisk = 100 - safeScore;
          }

          renderScore(finalRisk);

          // ====== Texto de nivel de riesgo ======
          function riskLabel(v) {
            if (v >= 80) return "Crítico";
            if (v >= 60) return "Alto";
            if (v >= 40) return "Moderado";
            if (v > 0) return "Bajo";
            return "Desconocido";
          }

          const riskLevelEl = document.getElementById("risk-level");
          const riskTypeEl = document.getElementById("risk-type");

          if (riskLevelEl) riskLevelEl.textContent = riskLabel(finalRisk);

          if (riskTypeEl) {
            if (cybScore != null) {
              if (cybScore >= 90) {
                riskTypeEl.textContent =
                  "Score CybFox muy bajo (sitio generalmente confiable)";
              } else if (cybScore >= 70) {
                riskTypeEl.textContent =
                  "Score CybFox medio/bajo (recomendado navegar con precaución)";
              } else if (cybScore >= 40) {
                riskTypeEl.textContent =
                  "Score CybFox alto (indicios de comportamiento riesgoso)";
              } else {
                riskTypeEl.textContent =
                  "Score CybFox muy alto (recomendado NO continuar)";
              }
            } else if (total === 0) {
              riskTypeEl.textContent =
                "Sin datos aún: análisis en curso o solo listado como sospechoso";
            } else if (stats.malicious > 0) {
              riskTypeEl.textContent = "Detectado como malicioso en VirusTotal";
            } else if (stats.suspicious > 0) {
              riskTypeEl.textContent = "Detectado como sospechoso en VirusTotal";
            } else {
              riskTypeEl.textContent = "Sin detecciones en VirusTotal";
            }
          }

          // ====== Badges VT ======
          const vtBox = document.getElementById("vt-badges");
          if (vtBox) {
            vtBox.innerHTML = "";

            const colors = {
              malicious: "red",
              suspicious: "yellow",
              harmless: "green",
              undetected: "gray"
            };

            Object.entries(stats).forEach(([name, val]) => {
              const chip = document.createElement("div");
              chip.className = `vt-badge ${colors[name]}`;
              chip.innerHTML = `<strong>${name}:</strong> ${val}`;
              vtBox.appendChild(chip);
            });

            if (total === 0) {
              const info = document.createElement("div");
              info.className = "vt-badge gray";
              info.textContent =
                "Sin información disponible de VirusTotal aún";
              vtBox.appendChild(info);
            }
          }

          // ====== Certificado SSL ======
          const crtEl = document.getElementById("crt-text");
          if (crtEl) crtEl.textContent = crt.https ? "Válido" : "No válido";

          // ====== Último escaneo ======
          const lastScanEl = document.getElementById("last-scan");
          if (lastScanEl) lastScanEl.textContent = meta.lastScanned || "—";
        } catch (e) {
          console.error("[CybFox] Error procesando datos en blocked.js:", e);
        }
      }
    );

    // ========= Donut =========
    function renderScore(score) {
      const canvas = document.getElementById("scoreChart");
      const scoreTextEl = document.getElementById("scoreText");
      if (!canvas || !scoreTextEl) return;

      const dpr = window.devicePixelRatio || 1;
      const size = 200;

      canvas.width = size * dpr;
      canvas.height = size * dpr;
      canvas.style.width = size + "px";
      canvas.style.height = size + "px";

      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      const center = size / 2;
      const radius = size / 2 - 18;
      const lw = 18;

      ctx.clearRect(0, 0, size, size);

      // anillo base
      ctx.beginPath();
      ctx.lineWidth = lw;
      ctx.strokeStyle = "rgba(15, 23, 42, 0.95)";
      ctx.arc(center, center, radius, 0, Math.PI * 2);
      ctx.stroke();

      const safeScore = Math.max(0, Math.min(100, score || 0));
      const start = -Math.PI / 2;
      const end = start + (Math.PI * 2 * safeScore) / 100;

      const grad = ctx.createLinearGradient(
        center - radius,
        center,
        center + radius,
        center
      );
      grad.addColorStop(0, "#22c55e");   // verde
      grad.addColorStop(0.5, "#eab308"); // amarillo
      grad.addColorStop(1, "#ef4444");   // rojo

      ctx.beginPath();
      ctx.lineWidth = lw;
      ctx.strokeStyle = grad;
      ctx.arc(center, center, radius, start, end);
      ctx.stroke();

      scoreTextEl.textContent = isNaN(safeScore)
        ? "—"
        : String(Math.round(safeScore));
    }

    // ====== Botones ======
    const backBtn = document.getElementById("btn-back");
    if (backBtn) {
      backBtn.onclick = () => {
        if (history.length > 1) history.back();
        else window.location.href = "about:blank";
      };
    }

    const dashBtn = document.getElementById("btn-dashboard");
    if (dashBtn) {
      dashBtn.onclick = () => {
        const url = chrome.runtime.getURL(
          "frontend/dist/index.html?view=dashboard"
        );
        chrome.tabs.create({ url });
      };
    }

    const unsafeBtn = document.getElementById("btn-unsafe");
    if (unsafeBtn) {
      if (!fullUrl) {
        unsafeBtn.disabled = true;
        unsafeBtn.title = "No se pudo recuperar la URL original.";
      } else {
        unsafeBtn.onclick = () => {
          // Permitimos temporalmente esta URL y redirigimos
          chrome.runtime.sendMessage(
            { type: "ALLOW_TEMP", url: fullUrl },
            () => {
              window.location.href = fullUrl;
            }
          );
        };
      }
    }
  } catch (e) {
    console.error("[CybFox] Error inicial en blocked.js:", e);
  }
})();
