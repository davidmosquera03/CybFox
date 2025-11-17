(async () => {
  const params = new URLSearchParams(window.location.search);
  const url = params.get("url") || "";

  const urlSpan = document.getElementById("url-text");
  const domainSpan = document.getElementById("domain-text");

  if (urlSpan) urlSpan.textContent = url || "URL no disponible";

  let domain = "Este sitio";
  if (url) {
    try {
      domain = new URL(url).hostname;
    } catch {
      domain = url;
    }
  }
  if (domainSpan) domainSpan.textContent = domain;

  const safeUrl = encodeURIComponent(url);
  const hostname = new URL(url).hostname;

  async function safeJSON(res) {
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch {
      return { error: "Invalid JSON", raw: text };
    }
  }

  // ====== PETICIONES AL BACKEND ======
  const vt = await fetch(`http://localhost:3000/api/check-vt?url=${safeUrl}`)
    .then(safeJSON)
    .catch(() => ({}));

  const ipqs = await fetch(`http://localhost:3000/api/check-ipqs?url=${safeUrl}`)
    .then(safeJSON)
    .catch(() => ({ risk_score: 0 }));

  const crt = await fetch(
    `http://localhost:3000/api/check-crt?domain=${hostname}`,
  )
    .then(safeJSON)
    .catch(() => ({ https: false }));

  const db = await fetch(
    `http://localhost:3000/api/db/get-page/${safeUrl}`,
  )
    .then(safeJSON)
    .catch(() => ({}));

  // ====== SCORE IPQS EN GRÁFICA DE DONUT (MEJORADO) ======
  const score = Number(ipqs.risk_score ?? 0);

  const canvas = document.getElementById("scoreChart");
  const scoreTextEl = document.getElementById("scoreText");

  if (canvas && scoreTextEl) {
    const dpr = window.devicePixelRatio || 1;
    const size = 200;

    // preparar canvas HD
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = size + "px";
    canvas.style.height = size + "px";

    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    const center = size / 2;
    const radius = size / 2 - 18;
    const lineWidth = 18;

    function drawScore(percent) {
      ctx.clearRect(0, 0, size, size);

      // anillo base
      ctx.beginPath();
      ctx.lineWidth = lineWidth;
      ctx.strokeStyle = "rgba(15, 23, 42, 0.95)";
      ctx.lineCap = "round";
      ctx.arc(center, center, radius, 0, Math.PI * 2);
      ctx.stroke();

      // glow suave
      if (percent > 0) {
        ctx.beginPath();
        ctx.lineWidth = lineWidth + 6;
        ctx.strokeStyle = "rgba(249, 115, 22, 0.15)";
        const glowEnd =
          -Math.PI / 2 + (Math.PI * 2 * Math.max(percent, 0)) / 100;
        ctx.arc(center, center, radius, -Math.PI / 2, glowEnd);
        ctx.stroke();
      }

      // arco principal con gradiente verde → amarillo → rojo
      if (percent > 0) {
        const startAngle = -Math.PI / 2;
        const endAngle = startAngle + (Math.PI * 2 * percent) / 100;

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
        ctx.lineWidth = lineWidth;
        ctx.strokeStyle = grad;
        ctx.lineCap = "round";
        ctx.arc(center, center, radius, startAngle, endAngle);
        ctx.stroke();
      }

      // número en el centro
      const display = isNaN(percent) ? "—" : String(Math.round(percent));
      scoreTextEl.textContent = display;
    }

    function animateScore(target) {
      let current = 0;

      function step() {
        current += (target - current) * 0.15; // easing
        if (Math.abs(target - current) < 0.5) {
          current = target;
        }
        const clamped = Math.max(0, Math.min(100, current));
        drawScore(clamped);

        if (current !== target) {
          requestAnimationFrame(step);
        }
      }

      step();
    }

    animateScore(score || 0);
  } else {
    // fallback por si no existe el canvas
    if (scoreTextEl) {
      scoreTextEl.textContent = isNaN(score) ? "—" : String(score);
    }
  }

  // ====== NIVEL DE RIESGO (texto) ======
  const riskLevelEl = document.getElementById("risk-level");
  const riskTypeEl = document.getElementById("risk-type");

  function riskLabel(v) {
    if (v >= 80) return "Crítico";
    if (v >= 60) return "Alto";
    if (v >= 40) return "Moderado";
    if (v > 0) return "Bajo";
    return "Desconocido";
  }

  const level = riskLabel(score);
  if (riskLevelEl) riskLevelEl.textContent = level;

  const typeFromIpqs =
    ipqs.category ||
    (ipqs.threats && Object.keys(ipqs.threats).filter(t => ipqs.threats[t]).join(", "));

  const typeFromVt =
    vt.malicious > 0 || vt.suspicious > 0
      ? "Phishing / contenido sospechoso"
      : "Contenido potencialmente no seguro";

  if (riskTypeEl) {
    riskTypeEl.textContent = typeFromIpqs || typeFromVt || "Sin clasificar";
  }

  // ====== SSL ====== 
  document.getElementById("crt-text").textContent = crt.https
    ? "Válido"
    : "No válido";

  // ====== ÚLTIMO ESCANEO ======
  document.getElementById("last-scan").textContent =
    db.lastScanned || "—";

  // ====== BADGES DE VIRUSTOTAL ======
  const vtBox = document.getElementById("vt-badges");

  const vtStats = {
    malicious: vt.malicious,
    suspicious: vt.suspicious,
    harmless: vt.harmless,
    undetected: vt.undetected,
  };

  const colors = {
    malicious: "red",
    suspicious: "yellow",
    harmless: "green",
    undetected: "gray",
  };

  Object.entries(vtStats).forEach(([name, val]) => {
    if (val === undefined) return;
    const badge = document.createElement("div");
    badge.className = `vt-badge ${colors[name]}`;
    badge.innerHTML = `<strong>${name}:</strong> ${val}`;
    vtBox.appendChild(badge);
  });

  if (!vt || vt.error) {
    const badge = document.createElement("div");
    badge.className = "vt-badge gray";
    badge.textContent = "No se pudo obtener info de VirusTotal";
    vtBox.appendChild(badge);
  }

  // ====== TEXTO RESUMEN DE IPQS (sin JSON plano feo) ======
  const ipqsEl = document.getElementById("ipqs-text");

  const ipqsPieces = [];
  if (typeof ipqs.unsafe === "boolean") {
    ipqsPieces.push(`unsafe: ${ipqs.unsafe ? "sí" : "no"}`);
  }
  if (ipqs.risk_score !== undefined) {
    ipqsPieces.push(`risk_score: ${ipqs.risk_score}`);
  }
  if (ipqs.root_domain) {
    ipqsPieces.push(`root_domain: ${ipqs.root_domain}`);
  }
  if (ipqs.category) {
    ipqsPieces.push(`category: ${ipqs.category}`);
  }
  if (ipqs.threats) {
    const activeThreats = Object.entries(ipqs.threats)
      .filter(([, v]) => v)
      .map(([k]) => k)
      .join(", ");
    if (activeThreats) {
      ipqsPieces.push(`threats: ${activeThreats}`);
    }
  }

  ipqsEl.textContent = ipqsPieces.length
    ? ipqsPieces.join(" · ")
    : "Sin datos adicionales de IPQS";

  // ====== BOTONES ======
  document.getElementById("btn-back").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "about:blank";
    }
  });

  document
    .getElementById("btn-dashboard")
    .addEventListener("click", () => {
      try {
        chrome.runtime.sendMessage({ type: "OPEN_DASHBOARD" });
      } catch (err) {
        console.warn("No se pudo abrir el dashboard", err);
      }
    });
})();
