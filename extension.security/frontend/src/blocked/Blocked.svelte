<script>
  import { onMount } from "svelte";

  const API_BASE = "http://localhost:3000";

  let url = "";
  let domain = "";
  let loading = true;
  let error = "";

  let riskLevel = "Analizando...";
  let riskChip = "Consultando VirusTotal...";
  let vtData = null;       // datos crudos de VT (para debug)
  let lastAnalysis = "";   // fecha/hora del análisis

  // --- Helpers -----------------------------------------------------

  function extractDomainFromUrl(raw) {
    try {
      return new URL(raw).hostname;
    } catch {
      return raw;
    }
  }

  // Intenta adaptarse a varias formas típicas de respuesta de VT.
  function getMaliciousStats(data) {
    if (!data) return { malicious: 0, suspicious: 0 };

    // Casos típicos (ajusta a tu JSON real si hace falta):
    if (data.stats) {
      return {
        malicious: data.stats.malicious ?? 0,
        suspicious: data.stats.suspicious ?? 0,
      };
    }

    return {
      malicious: data.malicious ?? data.malicious_count ?? 0,
      suspicious: data.suspicious ?? 0,
    };
  }

  function classifyRisk(data) {
    const { malicious, suspicious } = getMaliciousStats(data);

    if (malicious >= 5 || malicious + suspicious >= 10) {
      return {
        level: "Crítico",
        chip: "Malware / phishing confirmado",
      };
    }

    if (malicious > 0 || suspicious >= 3) {
      return {
        level: "Alto",
        chip: "Phishing / contenido sospechoso",
      };
    }

    if (suspicious > 0) {
      return {
        level: "Medio",
        chip: "Riesgo moderado",
      };
    }

    return {
      level: "Bajo",
      chip: "Sin detecciones relevantes",
    };
  }

  function formatDateFromUnix(ts) {
    if (!ts) return "";
    try {
      const d = new Date(ts * 1000);
      return d.toLocaleString();
    } catch {
      return "";
    }
  }

  // --- Carga de datos desde el backend -----------------------------

  async function loadData() {
    try {
      loading = true;
      error = "";

      const params = new URLSearchParams(window.location.search);
      url = params.get("url") || window.location.href;
      domain = extractDomainFromUrl(url);

      const res = await fetch(
        `${API_BASE}/api/check-vt?url=${encodeURIComponent(url)}`
      );

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const payload = await res.json();

      // Intenta agarrar el objeto interesante según cómo hayas armado la ruta.
      // Ajusta estas líneas cuando veas el JSON real en consola.
      vtData =
        payload.data ||
        payload.result ||
        payload.vt ||
        payload.analysis ||
        payload;

      console.log("VirusTotal payload en blocked:", vtData);

      const { level, chip } = classifyRisk(vtData);
      riskLevel = level;
      riskChip = chip;

      // Intenta leer fecha de análisis
      const ts =
        vtData.last_analysis_date ||
        vtData.last_analysis_timestamp ||
        vtData.last_update;
      lastAnalysis = formatDateFromUnix(ts);
    } catch (e) {
      console.error("Error al consultar VirusTotal desde blocked:", e);
      error = "No se pudo obtener los detalles técnicos de VirusTotal.";
      riskLevel = "Desconocido";
      riskChip = "Error al consultar VirusTotal";
    } finally {
      loading = false;
    }
  }

  // --- Botones -----------------------------------------------------

  function goBack() {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "about:blank";
    }
  }

  function openDashboard() {
    try {
      chrome.runtime.sendMessage({
        type: "OPEN_DASHBOARD",
        url,
        domain,
      });
    } catch (e) {
      console.warn("No se pudo abrir el dashboard", e);
    }
  }

  onMount(loadData);
</script>

<main class="page">
  <div class="card">
    <div class="glow"></div>

    <header class="header">
      <div class="brand">
        <div class="brand-logo">🦊</div>
        <div class="brand-text">
          <span class="brand-name">CybFox</span>
          <span class="brand-tagline">URL Safety Checker</span>
        </div>
      </div>

      <span class="pill">Acceso bloqueado</span>
    </header>

    <section class="body">
      <h1>Este sitio ha sido bloqueado</h1>

      <p class="domain">{domain || "Este sitio"}</p>

      <p class="msg">
        Hemos detectado patrones de riesgo en esta página. Para proteger tu
        navegación, CybFox ha bloqueado el acceso directo.
      </p>

      <div class="risk-box">
        <div class="risk-label">Nivel de riesgo</div>

        <div class="risk-value">
          {riskLevel}
          <span class="risk-chip">{riskChip}</span>
        </div>
      </div>

      <ul class="details">
        <li>
          <span class="label">URL detectada</span>
          <span class="value url">{url}</span>
        </li>
        <li>
          <span class="label">Último análisis</span>
          <span class="value">{lastAnalysis || "Sin fecha disponible"}</span>
        </li>
        <li>
          <span class="label">Estado de la consulta</span>
          <span class="value">
            {#if loading}
              Consultando VirusTotal...
            {:else if error}
              {error}
            {:else}
              Datos cargados desde VirusTotal.
            {/if}
          </span>
        </li>
      </ul>

      {#if vtData}
        <details class="technical">
          <summary>Ver detalles técnicos (JSON)</summary>
          <pre>{JSON.stringify(vtData, null, 2)}</pre>
        </details>
      {/if}
    </section>

    <footer class="footer">
      <button class="btn btn-ghost" on:click={goBack}>
        Volver a la página anterior
      </button>

      <button class="btn btn-primary" on:click={openDashboard}>
        Ver detalles en el dashboard
      </button>
    </footer>
  </div>
</main>

<style>
  :global(body) {
    margin: 0;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI",
      sans-serif;
    background: radial-gradient(circle at top, #0f172a, #020617 60%);
    color: #e5e7eb;
  }

  .page {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 32px 16px;
  }

  .card {
    position: relative;
    width: 100%;
    max-width: 920px;
    border-radius: 24px;
    padding: 32px 32px 24px;
    background: radial-gradient(circle at top left, #1f2937, #020617 60%);
    border: 1px solid rgba(148, 163, 184, 0.4);
    box-shadow:
      0 24px 80px rgba(15, 23, 42, 0.9),
      0 0 0 1px rgba(15, 23, 42, 0.6);
    overflow: hidden;
  }

  .glow {
    position: absolute;
    inset: -40%;
    background: radial-gradient(circle at 0% 0%, #f97316 0, transparent 55%);
    opacity: 0.28;
    pointer-events: none;
  }

  .header,
  .body,
  .footer {
    position: relative;
    z-index: 1;
  }

  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 24px;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .brand-logo {
    width: 40px;
    height: 40px;
    border-radius: 999px;
    display: grid;
    place-items: center;
    font-size: 22px;
    background: radial-gradient(circle at 30% 0, #fed7aa, #f97316 65%, #7c2d12);
    box-shadow: 0 0 0 2px rgba(15, 23, 42, 0.9),
      0 12px 30px rgba(248, 113, 113, 0.7);
  }

  .brand-text {
    display: flex;
    flex-direction: column;
  }

  .brand-name {
    font-weight: 600;
    letter-spacing: 0.02em;
  }

  .brand-tagline {
    font-size: 12px;
    color: #9ca3af;
  }

  .pill {
    padding: 6px 12px;
    border-radius: 999px;
    border: 1px solid rgba(248, 113, 113, 0.9);
    font-size: 12px;
    color: #fecaca;
    background: linear-gradient(
      135deg,
      rgba(185, 28, 28, 0.4),
      rgba(127, 29, 29, 0.25)
    );
  }

  .body h1 {
    font-size: 22px;
    margin: 0 0 4px;
  }

  .domain {
    font-size: 14px;
    color: #9ca3af;
    margin: 0 0 16px;
  }

  .msg {
    font-size: 14px;
    color: #e5e7eb;
    max-width: 620px;
    margin-bottom: 20px;
  }

  .risk-box {
    margin-bottom: 20px;
    padding: 14px 16px;
    border-radius: 16px;
    border: 1px solid rgba(248, 113, 113, 0.5);
    background: radial-gradient(circle at top left, #1e293b, #020617 75%);
  }

  .risk-label {
    font-size: 12px;
    text-transform: uppercase;
    color: #9ca3af;
    letter-spacing: 0.13em;
    margin-bottom: 4px;
  }

  .risk-value {
    font-size: 16px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .risk-chip {
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 11px;
    border: 1px solid rgba(251, 146, 60, 0.8);
    background: linear-gradient(
      135deg,
      rgba(251, 146, 60, 0.45),
      rgba(248, 113, 113, 0.4)
    );
    color: #0b1120;
  }

  .details {
    list-style: none;
    padding: 0;
    margin: 0 0 8px;
    display: grid;
    gap: 8px;
  }

  .details li {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .label {
    font-size: 11px;
    text-transform: uppercase;
    color: #9ca3af;
    letter-spacing: 0.12em;
  }

  .value {
    font-size: 13px;
  }

  .url {
    word-break: break-all;
    color: #bfdbfe;
  }

  .technical {
    margin-top: 12px;
    font-size: 12px;
    color: #9ca3af;
  }

  .technical summary {
    cursor: pointer;
    margin-bottom: 4px;
  }

  .technical pre {
    max-height: 220px;
    overflow: auto;
    padding: 10px 12px;
    border-radius: 10px;
    background: rgba(15, 23, 42, 0.9);
    border: 1px solid rgba(30, 64, 175, 0.6);
    color: #e5e7eb;
  }

  .footer {
    margin-top: 20px;
    display: flex;
    justify-content: flex-end;
    gap: 10px;
  }

  .btn {
    border-radius: 999px;
    padding: 8px 16px;
    font-size: 13px;
    border: 1px solid transparent;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .btn-ghost {
    background: transparent;
    border-color: rgba(148, 163, 184, 0.6);
    color: #e5e7eb;
  }

  .btn-ghost:hover {
    background: rgba(15, 23, 42, 0.7);
  }

  .btn-primary {
    background: linear-gradient(135deg, #fb923c, #f97316);
    color: #0b1120;
    font-weight: 600;
    box-shadow: 0 14px 40px rgba(248, 113, 113, 0.65);
  }

  .btn-primary:hover {
    filter: brightness(1.05);
  }

  @media (max-width: 720px) {
    .card {
      padding: 24px 20px 18px;
      border-radius: 20px;
    }

    .header {
      flex-direction: column;
      align-items: flex-start;
    }

    .footer {
      flex-direction: column-reverse;
      align-items: stretch;
    }

    .btn {
      width: 100%;
      justify-content: center;
    }
  }
</style>
