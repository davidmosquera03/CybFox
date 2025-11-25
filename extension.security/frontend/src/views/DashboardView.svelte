<script lang="ts">

  import ChatWrapper from "./ChatWrapper.svelte";
  import ChatButton from "./ChatButton.svelte";


  import { onMount } from "svelte";
  import logoDashDark from "../assets/logo-dash-oscuro.png";
  import logoDashLight from "../assets/logo-dash-claro.png";

  const API_BASE = "http://localhost:3000/api";


  let showChat = false;

  const toggleChat = () => {
    showChat = !showChat;
  };

  const closeChat = () => {
    showChat = false;
  };

  // ====== ESTADO GLOBAL ======

  let theme: "dark" | "light" = "dark";

  $: dashboardLogo = theme === "dark" ? logoDashDark : logoDashLight;

  let loading = true;
  let loadError = "";

  // Página actual (pasada por ?url=... desde la extensión o tomada del historial)
  let currentUrl = "";
  let domain = "";

  // Guarda el último dominio escaneado por si entran al dashboard “vacío”
  let latestDomain = "";
  let allPages: any[] = [];

  // Info detallada de la página
  let pageInfo: any = null;
  let ipqsData: any = null;
  let vtStats: any = null;
  let crtInfo: any = null;

  // Stats globales
  let totalPages = 0;
  let safePages = 0;
  let lowRiskPages = 0;
  let mediumRiskPages = 0;
  let highRiskPages = 0;
  let recentPages: any[] = [];

  // Listas
  let blacklist: any[] = [];
  let whitelist: any[] = [];
  let blacklistInput = "";
  let whitelistInput = "";
  let blacklistSearch = "";
  let whitelistSearch = "";
  let togglingBlacklist = false;
  let togglingWhitelist = false;
  let toggleMessage = "";

  // Panel IPQS / VT
  let showIpqsDetails = false;
  let scanningIpqs = false;
  let ipqsMessage = "";
  let scanningVt = false;
  let vtMessage = "";

  // Etiquetas combinadas (popup + IPQS + VT)
  let derivedTags: string[] = [];

  // Derivados
  let ipqsRiskScore: number | null = null;
  let cybfoxScoreSafe: number | null = null; // confianza 0–100
  let cybfoxRisk: number | null = null; // 0 = seguro, 100 = muy riesgoso
  let vtStatsEffective: any = null;
  let vtSummary: any = null;
  let trafficState: "low" | "medium" | "high" = "medium";
  let globalRiskTotal = 0;
  let filteredBlacklist: any[] = [];
  let filteredWhitelist: any[] = [];
   // ====== CONTEXTO PARA CYBFOX AI (CHAT) ======
  $: dashboardContext = {
    currentUrl,
    domain,
    trafficState,
    ipqsRiskScore,
    cybfoxScoreSafe,
    cybfoxRisk,
    ipqsData,
    vtStats: vtStatsEffective,
    vtSummary,
    crtInfo,
    derivedTags,
    totals: {
      totalPages,
      safePages,
      lowRiskPages,
      mediumRiskPages,
      highRiskPages,
    },
    recentPages,
    blacklist,
    whitelist,
  };


  // ====== THEME ======
  function applyTheme() {
    if (typeof document === "undefined") return;
    const root = document.documentElement;
    root.dataset.theme = theme;
    localStorage.setItem("cybfox-theme", theme);
  }

  function toggleTheme() {
    theme = theme === "dark" ? "light" : "dark";
    applyTheme();
  }

  // ====== URL ACTUAL ======
  function initFromLocation() {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const urlParam =
      params.get("url") ||
      params.get("domain") ||
      params.get("page") ||
      params.get("target") ||
      "";

    currentUrl = urlParam;

    if (urlParam) {
      try {
        // Si viene una URL completa (https://...), sacamos hostname
        const u = new URL(urlParam);
        domain = u.hostname;
      } catch {
        // Si viene solo el dominio (enter.co) lo usamos tal cual
        domain = urlParam;
      }
    } else {
      domain = "";
    }
  }

  // ====== HELPERS FETCH ======
  async function safeJson(res: Response) {
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  }

  // ====== CARGA DE DATOS ======
  async function loadPageInfo() {
    // Usamos SIEMPRE el dominio para consultar la página en la BD
    const lookupKey = domain || currentUrl;

    if (!lookupKey) {
      pageInfo = null;
      ipqsData = null;
      vtStats = null;
      crtInfo = null;
      return;
    }

    try {
      const encoded = encodeURIComponent(lookupKey);
      const res = await fetch(`${API_BASE}/db/get-page/${encoded}`);
      const json = await safeJson(res);

      if (!res.ok || !json.success) {
        loadError = json.message || "No se pudo cargar la página analizada.";
        pageInfo = null;
        ipqsData = null;
        vtStats = null;
        crtInfo = null;
        return;
      }

      pageInfo = json.page;

      const reports: any[] = pageInfo.reports || [];

      const ipqsEntry = reports.find((r) => r.source === "IPQS");
      ipqsData = ipqsEntry ? ipqsEntry.data : null;

      const vtEntry = reports.find((r) => r.source === "VirusTotal");
      vtStats = vtEntry ? vtEntry.data : null;

      const crtEntry = reports.find((r) => r.source === "CRT");
      crtInfo = crtEntry ? crtEntry.data : null;

      loadError = "";
    } catch (e) {
      console.error(e);
      loadError = "Error de red al cargar la página analizada.";
    }
  }

  async function loadGlobalStats() {
    try {
      const res = await fetch(`${API_BASE}/db/get-all-pages`);
      const json = await safeJson(res);
      if (!res.ok || !json.success) return;

      const pages: any[] = json.pages || [];
      allPages = pages;
      totalPages = json.count || pages.length;

      let safe = 0;
      let low = 0;
      let med = 0;
      let high = 0;

      // currentScore = confianza (0 = malo, 100 = muy confiable)
      // riesgo = 100 - currentScore
      pages.forEach((p) => {
        const safeScore = Math.max(0, Math.min(100, p.currentScore ?? 0));
        const risk = 100 - safeScore;

        if (risk <= 20) safe++;
        else if (risk <= 40) low++;
        else if (risk <= 70) med++;
        else high++;
      });

      safePages = safe;
      lowRiskPages = low;
      mediumRiskPages = med;
      highRiskPages = high;

      recentPages = pages.slice(-5).reverse();

      // último dominio escaneado (el último del array)
      latestDomain = pages.length ? pages[pages.length - 1].url : "";
    } catch (e) {
      console.error(e);
    }
  }

  async function loadBlacklist() {
    try {
      const res = await fetch(`${API_BASE}/db/get-blacklist`);
      const json = await safeJson(res);
      if (!res.ok || !json.success) return;
      blacklist = json.blacklist || [];
    } catch (e) {
      console.error(e);
    }
  }

  async function loadWhitelist() {
    try {
      const res = await fetch(`${API_BASE}/db/get-whitelist`);
      const json = await safeJson(res);
      if (!res.ok || !json.success) return;
      whitelist = json.whitelist || [];
    } catch (e) {
      console.error(e);
    }
  }

  async function toggleBlacklistUrl(url: string) {
    if (!url) return;
    try {
      togglingBlacklist = true;
      toggleMessage = "";
      await fetch(`${API_BASE}/db/toggle-blacklist`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      await Promise.all([loadBlacklist(), loadWhitelist(), loadPageInfo()]);
      blacklistInput = "";
    } catch (e) {
      console.error(e);
      toggleMessage = "No se pudo actualizar la lista de bloqueados.";
    } finally {
      togglingBlacklist = false;
    }
  }

  async function toggleWhitelistUrl(url: string) {
    if (!url) return;
    try {
      togglingWhitelist = true;
      toggleMessage = "";
      const res = await fetch(`${API_BASE}/db/toggle-whitelist`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const json = await safeJson(res);
      if (!res.ok && json.message) {
        toggleMessage = json.message;
      }
      await Promise.all([loadWhitelist(), loadBlacklist(), loadPageInfo()]);
      whitelistInput = "";
    } catch (e) {
      console.error(e);
      toggleMessage = "No se pudo actualizar la lista blanca.";
    } finally {
      togglingWhitelist = false;
    }
  }

  // ====== ESCANEOS MANUALES ======
  async function runIpqsScan() {
    if (!currentUrl || scanningIpqs) return;
    try {
      scanningIpqs = true;
      ipqsMessage = "";
      const encoded = encodeURIComponent(currentUrl);
      const res = await fetch(`${API_BASE}/check-ipqs?url=${encoded}`);
      const json = await safeJson(res);
      if (!res.ok) {
        ipqsMessage = json.message || "No se pudo obtener información de IPQS.";
      } else {
        ipqsData = json;
        await Promise.all([loadPageInfo(), loadGlobalStats()]);
      }
    } catch (e) {
      console.error(e);
      ipqsMessage = "Error de red con IPQS.";
    } finally {
      scanningIpqs = false;
    }
  }

  async function runVirusTotalScan() {
    if (!currentUrl || scanningVt) return;
    try {
      scanningVt = true;
      vtMessage = "";
      const encoded = encodeURIComponent(currentUrl);
      const res = await fetch(`${API_BASE}/check-vt?url=${encoded}`);
      const json = await safeJson(res);
      if (!res.ok || !json.success) {
        vtMessage =
          json.message ||
          "No se pudo obtener información de VirusTotal en este momento.";
      } else {
        vtStats = json.stats;
        await Promise.all([loadPageInfo(), loadGlobalStats()]);
      }
    } catch (e) {
      console.error(e);
      vtMessage = "Error de red con VirusTotal.";
    } finally {
      scanningVt = false;
    }
  }

  // ====== DERIVADOS ======
  $: ipqsRiskScore =
    ipqsData && typeof ipqsData.risk_score === "number"
      ? ipqsData.risk_score
      : pageInfo &&
          pageInfo.reports &&
          pageInfo.reports.find((r: any) => r.source === "IPQS") &&
          typeof pageInfo.reports.find((r: any) => r.source === "IPQS").data
            ?.risk_score === "number"
        ? pageInfo.reports.find((r: any) => r.source === "IPQS").data.risk_score
        : null;

  // Score CybFox de confianza (0 = peor, 100 = más confiable)
  $: cybfoxScoreSafe =
    pageInfo && typeof pageInfo.currentScore === "number"
      ? pageInfo.currentScore
      : null;

  // Riesgo CybFox (0 = seguro, 100 = muy riesgoso)
  $: cybfoxRisk =
    cybfoxScoreSafe != null
      ? 100 - Math.max(0, Math.min(100, cybfoxScoreSafe))
      : null;

  $: vtStatsEffective = vtStats
    ? vtStats
    : pageInfo &&
        pageInfo.reports &&
        pageInfo.reports.find((r: any) => r.source === "VirusTotal")
      ? pageInfo.reports.find((r: any) => r.source === "VirusTotal").data
      : null;

  $: vtSummary = (() => {
    if (!vtStatsEffective) return null;

    const harmless = vtStatsEffective.harmless ?? 0;
    const malicious = vtStatsEffective.malicious ?? 0;
    const suspicious = vtStatsEffective.suspicious ?? 0;
    const undetected = vtStatsEffective.undetected ?? 0;
    const timeout = vtStatsEffective.timeout ?? 0;

    let total = harmless + malicious + suspicious + undetected + timeout;

    // 💡 Si VirusTotal devuelve todo 0, pintamos el donut como "todo inofensivo"
    if (total === 0) {
      return {
        harmless: 1,
        malicious: 0,
        suspicious: 0,
        undetected: 0,
        timeout: 0,
        total: 1,
        empty: true, // marca que en realidad no había datos
      };
    }

    return {
      harmless,
      malicious,
      suspicious,
      undetected,
      timeout,
      total,
      empty: false,
    };
  })();

  // Semáforo (prioriza IPQS; si no hay, usa CybFox)
  $: {
    const ipqsScore = typeof ipqsRiskScore === "number" ? ipqsRiskScore : null;

    if (ipqsScore !== null) {
      if (ipqsScore >= 80) trafficState = "high";
      else if (ipqsScore >= 50) trafficState = "medium";
      else trafficState = "low";
    } else if (cybfoxRisk !== null) {
      if (cybfoxRisk >= 80) trafficState = "high";
      else if (cybfoxRisk >= 50) trafficState = "medium";
      else trafficState = "low";
    } else {
      trafficState = "medium";
    }
  }

  $: globalRiskTotal =
    safePages + lowRiskPages + mediumRiskPages + highRiskPages;

  $: filteredBlacklist = blacklistSearch
    ? blacklist.filter((i) =>
        i.url.toLowerCase().includes(blacklistSearch.toLowerCase()),
      )
    : blacklist;

  $: filteredWhitelist = whitelistSearch
    ? whitelist.filter((i) =>
        i.url.toLowerCase().includes(whitelistSearch.toLowerCase()),
      )
    : whitelist;

  // ====== ETIQUETAS: popup + IPQS + VirusTotal ======
  $: derivedTags = (() => {
    const tags: string[] = [];

    // Tags que guardó el usuario desde el popup
    if (pageInfo?.tags && Array.isArray(pageInfo.tags)) {
      tags.push(...pageInfo.tags);
    }

    // Categoría general IPQS
    if (ipqsData?.category) {
      tags.push(`IPQS: ${ipqsData.category}`);
    }

    // Threat flags de IPQS
    if (ipqsData?.threats) {
      if (ipqsData.threats.phishing) tags.push("Phishing detectado");
      if (ipqsData.threats.malware) tags.push("Malware detectado");
      if (ipqsData.threats.spamming) tags.push("Spam / campañas masivas");
      if (ipqsData.threats.adult) tags.push("Contenido adulto");
      if (ipqsData.threats.suspicious) tags.push("Actividad sospechosa");
    }

    // Resumen VirusTotal
    if (vtSummary) {
      const hits = (vtSummary.malicious || 0) + (vtSummary.suspicious || 0);
      if (hits > 0) {
        tags.push("VirusTotal: motores detectan riesgo");
      } else if (vtSummary.harmless > 0 && !ipqsData?.unsafe) {
        tags.push("VirusTotal: sin detecciones");
      }
    }

    // Quitar duplicados
    return [...new Set(tags)];
  })();

  function formatDate(value: any) {
    if (!value) return "Sin dato";
    try {
      const d = new Date(value);
      return d.toLocaleString();
    } catch {
      return String(value);
    }
  }

  function formatScore(score: number | null | undefined) {
    if (score === null || score === undefined) return "--";
    return Math.round(score);
  }

  // ====== MONTAJE ======
  onMount(async () => {
    if (typeof window !== "undefined") {
      const savedTheme = localStorage.getItem("cybfox-theme") as
        | "dark"
        | "light"
        | null;
      if (savedTheme === "dark" || savedTheme === "light") {
        theme = savedTheme;
      }
      applyTheme();
    }

    // 1. Intentamos leer la URL que mandó la extensión
    initFromLocation();

    loading = true;

    // 2. Cargamos estadísticas globales (para poder tener latestDomain)
    await loadGlobalStats();

    // 3. Si NO vino url por querystring, usamos la última página analizada
    if (!currentUrl && latestDomain) {
      currentUrl = latestDomain;
      domain = latestDomain;
    }

    // 4. Cargamos info de la página + listas
    await Promise.all([loadPageInfo(), loadBlacklist(), loadWhitelist()]);

    loading = false;
  });
</script>

<ChatButton toggle={toggleChat} />

<ChatWrapper open={showChat} close={closeChat} dashboard={dashboardContext} />

<div class="dashboard-root">

  <div class="layout">
    <!-- SIDEBAR -->
    <aside class="side-nav">
      <div class="logo-block">
        <div class="logo-image">
          <img src={dashboardLogo} alt="CybFox logo" />
        </div>
        <div class="logo-text">
          <span class="logo-main">CYBFOX</span>
          <span class="logo-sub">Security Hub</span>
        </div>
      </div>

      <nav class="nav-links">
        <button class="nav-item active">
          <span class="nav-dot"></span>
          <span>Resumen</span>
        </button>
        <!-- <button class="nav-item">
          <span class="nav-dot"></span>
          <span>Análisis profundo</span>
        </button>
        <button class="nav-item">
          <span class="nav-dot"></span>
          <span>Análisis rápido</span>
        </button> -->
<!-- 
        <div class="nav-group-title">LISTAS</div>
        <button class="nav-item">
          <span class="nav-dot"></span>
          <span>Lista de bloqueados</span>
        </button>
        <button class="nav-item">
          <span class="nav-dot"></span>
          <span>Lista blanca</span>
        </button>

        <div class="nav-group-title">SISTEMA</div>
        <button class="nav-item">
          <span class="nav-dot"></span>
          <span>Configuración</span>
        </button> -->
      </nav>
    </aside>

    <!-- MAIN -->
    <main class="main-area">
      <header class="top-bar">
        <div class="top-left">
          <h1>Panel de seguridad</h1>
          <p class="subtitle">
            Vista general de tus análisis, bloqueos automáticos y listas
            personalizadas.
          </p>
        </div>

        <div class="top-controls">
          <button
            class="icon-btn"
            on:click={toggleTheme}
            aria-label="Cambiar tema"
          >
            {theme === "dark" ? "☀️" : "🌙"}
          </button>
        </div>
      </header>

      {#if loading}
        <div class="loading-state">
          <div class="spinner"></div>
          <span>Cargando información de CybFox…</span>
        </div>
      {:else}
        {#if loadError}
          <div class="error-banner">
            {loadError}
          </div>
        {/if}

        <!-- PÁGINA ANALIZADA -->
        <section class="section-card page-analyzed">
          <div class="section-header">
            <div>
              <h2>Página analizada</h2>
              {#if currentUrl}
                <div class="current-url">{currentUrl}</div>
              {:else}
                <div class="current-url muted">
                  Abre el dashboard desde la extensión para ver una página
                  específica.
                </div>
              {/if}
            </div>

            {#if currentUrl}
              <div class="risk-summary">
                <!-- Semáforo horizontal -->
                <div class="traffic-light">
                  <div
                    class="light light-red {trafficState === 'high'
                      ? 'active'
                      : ''}"
                  ></div>
                  <div
                    class="light light-amber {trafficState === 'medium'
                      ? 'active'
                      : ''}"
                  ></div>
                  <div
                    class="light light-green {trafficState === 'low'
                      ? 'active'
                      : ''}"
                  ></div>
                </div>
                <span class="badge-neon">
                  {#if trafficState === "high"}
                    Riesgo alto · recomendado bloquear
                  {:else if trafficState === "medium"}
                    Riesgo moderado · navegar con cuidado
                  {:else}
                    Riesgo bajo · sitio relativamente seguro
                  {/if}
                </span>
              </div>
            {/if}
          </div>

          <div class="page-grid">
            <div class="page-main">
              <!-- SCORES -->
              <div class="score-grid">
                <!-- IPQS -->

                <div
                  class="score-ring-card"
                  style={`--pct:${ipqsRiskScore ?? 0};`}
                >
                  <div class="score-ring">
                    <div class="score-ring-inner">
                      <div class="score-number">
                        {formatScore(ipqsRiskScore)}
                        <span class="score-unit">/ 100</span>
                      </div>
                      <div class="score-label">Riesgo IPQS</div>
                    </div>
                  </div>

                  <div class="score-meta">
                    <div class="score-chip ipqs">IPQS</div>
                    {#if ipqsRiskScore !== null}
                      <p class="muted">
                        Índice de riesgo devuelto por IPQS para este dominio.
                      </p>
                    {:else}
                      <p class="muted">
                        Aún no hay análisis guardado. Pulsa el botón para
                        analizar con IPQS.
                      </p>
                    {/if}
                    <button
                      class="btn-ghost small"
                      type="button"
                      disabled={!currentUrl || scanningIpqs}
                      on:click={runIpqsScan}
                    >
                      {#if scanningIpqs}
                        Analizando con IPQS…
                      {:else}
                        Analizar con IPQS
                      {/if}
                    </button>
                    {#if ipqsMessage}
                      <p class="muted small">{ipqsMessage}</p>
                    {/if}
                  </div>
                </div>

                <!-- CybFox -->
                <div class="score-card cybfox-card">
                  <div class="score-card-header">
                    <span class="score-title">Score CybFox</span>
                    <span class="score-chip cybfox">CybFox</span>
                  </div>
                  <div class="score-value-row">
                    <span class="score-value"
                      >{formatScore(cybfoxScoreSafe)}</span
                    >
                    <span class="score-unit">/100</span>
                  </div>
                  <p class="muted">
                    Score interno (0 = peor, 100 = más confiable)
                  </p>

                  {#if pageInfo}
                    <div class="badge-row">
                      {#if pageInfo.isBlacklisted}
                        <span class="tag-chip danger"
                          >En lista de bloqueados</span
                        >
                      {/if}
                      {#if pageInfo.isWhitelisted}
                        <span class="tag-chip success">En lista blanca</span>
                      {/if}
                      <span class="tag-chip ghost">
                        Último escaneo: {formatDate(pageInfo.lastScanned)}
                      </span>
                    </div>
                  {/if}
                </div>

                <!-- VirusTotal -->
                <div class="score-card virus-total-card">
                  <div class="score-card-header">
                    <span class="score-title">Detección VirusTotal</span>
                    <span class="score-chip vt">VirusTotal</span>
                  </div>

                  {#if vtSummary}
                    <div
                      class="vt-chart"
                      style={`--h:${vtSummary.harmless}; --m:${vtSummary.malicious}; --s:${vtSummary.suspicious}; --u:${vtSummary.undetected}; --t:${vtSummary.timeout};`}
                    >
                      <div class="vt-pie">
                        <div class="vt-pie-inner">
                          <div class="score-number small">
                            {vtSummary.malicious + vtSummary.suspicious}
                          </div>
                          <div class="score-label">motores en contra</div>
                        </div>
                      </div>
                      <ul class="vt-legend">
                        <li>
                          <span class="dot harmless"></span>Inofensivo ({vtSummary.harmless})
                        </li>
                        <li>
                          <span class="dot malicious"></span>Malicioso ({vtSummary.malicious})
                        </li>
                        <li>
                          <span class="dot suspicious"></span>Sospechoso ({vtSummary.suspicious})
                        </li>
                        <li>
                          <span class="dot undetected"></span>No detectado ({vtSummary.undetected})
                        </li>
                      </ul>
                    </div>
                  {:else}
                    <p class="muted small">
                      No hay análisis de VirusTotal guardado todavía para este
                      dominio.
                    </p>
                  {/if}

                  <button
                    class="btn-ghost small"
                    type="button"
                    disabled={!currentUrl || scanningVt}
                    on:click={runVirusTotalScan}
                  >
                    {#if scanningVt}
                      Analizando con VirusTotal…
                    {:else}
                      Actualizar VirusTotal
                    {/if}
                  </button>
                  {#if vtMessage}
                    <p class="muted small">{vtMessage}</p>
                  {/if}
                </div>
              </div>

              <!-- EVOLUCIÓN IPQS -->
              <div class="evolution-card">
                <div class="section-subheader">
                  <h3>Evolución del riesgo (IPQS)</h3>
                  <span class="muted small">
                    Basado en los últimos escaneos registrados.
                  </span>
                </div>

                {#if pageInfo && pageInfo.reports}
                  {#if pageInfo.reports.filter((r) => r.source === "IPQS").length === 0}
                    <p class="muted small">
                      Aún no hay suficientes escaneos IPQS para mostrar la
                      evolución.
                    </p>
                  {:else}
                    {#each pageInfo.reports
                      .filter((r) => r.source === "IPQS")
                      .slice(-4)
                      .reverse() as item (item.date)}
                      <div class="evo-row">
                        <div class="evo-date">{formatDate(item.date)}</div>
                        <div class="evo-bar-wrap">
                          <div
                            class="evo-bar"
                            style={`width: ${
                              item.data &&
                              typeof item.data.risk_score === "number"
                                ? item.data.risk_score
                                : 0
                            }%;`}
                          ></div>
                        </div>
                        <div class="evo-score">
                          {item.data && typeof item.data.risk_score === "number"
                            ? item.data.risk_score
                            : "--"}
                        </div>
                      </div>
                    {/each}
                  {/if}
                {:else}
                  <p class="muted small">
                    No hay datos de historial para esta página.
                  </p>
                {/if}
              </div>
            </div>

            <!-- LADO DERECHO -->
            <div class="page-side">
              <!-- CERTIFICADO -->
              <div class="card mini">
                <div class="section-subheader">
                  <h3>Certificado SSL/TLS</h3>
                </div>
                {#if crtInfo}
                  <ul class="simple-list">
                    <li>
                      <span class="label">Emisor</span>
                      <span class="value">{crtInfo.issuer || "—"}</span>
                    </li>
                    <li>
                      <span class="label">Válido desde</span>
                      <span class="value">{formatDate(crtInfo.valid_from)}</span
                      >
                    </li>
                    <li>
                      <span class="label">Válido hasta</span>
                      <span class="value">{formatDate(crtInfo.valid_to)}</span>
                    </li>
                    <li>
                      <span class="label">Coincide con el dominio</span>
                      <span class="value">
                        {crtInfo.domain_match ? "Sí" : "No"}
                      </span>
                    </li>
                  </ul>
                {:else}
                  <p class="muted small">
                    No hay certificado guardado todavía para este dominio.
                  </p>
                {/if}
              </div>

              <!-- TAGS (popup + IPQS + VT) -->
              <div class="card mini">
                <div class="section-subheader">
                  <h3>Etiquetas de la página</h3>
                  <span class="muted small">
                    Combinación de etiquetas que el usuario eligió en el popup,
                    más las generadas a partir de IPQS y VirusTotal.
                  </span>
                </div>
                <div class="tag-cloud">
                  {#if derivedTags.length > 0}
                    {#each derivedTags as tag}
                      <span class="tag-chip">{tag}</span>
                    {/each}
                  {:else}
                    <span class="muted small">Sin etiquetas guardadas.</span>
                  {/if}
                </div>
              </div>

              <!-- IPQS DETALLES -->
              <div class="card mini">
                <div class="section-subheader row">
                  <h3>Detalles IPQS</h3>
                  <button
                    class="small-link"
                    type="button"
                    on:click={() => (showIpqsDetails = !showIpqsDetails)}
                  >
                    {showIpqsDetails ? "Ocultar" : "Ver detalles"}
                  </button>
                </div>

                {#if ipqsData}
                  {#if showIpqsDetails}
                    <div class="ipqs-details">
                      <div class="ipqs-item">
                        <span class="label">Riesgo:</span>
                        <span class="value">
                          {formatScore(ipqsData.risk_score)} / 100
                        </span>
                      </div>
                      <div class="ipqs-item">
                        <span class="label">Dominio raíz:</span>
                        <span class="value">
                          {ipqsData.root_domain || domain || "—"}
                        </span>
                      </div>
                      <div class="ipqs-item">
                        <span class="label">Categoría:</span>
                        <span class="value">
                          {ipqsData.category || "—"}
                        </span>
                      </div>
                      <div class="ipqs-item">
                        <span class="label">Phishing:</span>
                        <span class="value">
                          {ipqsData.threats?.phishing ? "Sí" : "No"}
                        </span>
                      </div>
                      <div class="ipqs-item">
                        <span class="label">Malware:</span>
                        <span class="value">
                          {ipqsData.threats?.malware ? "Sí" : "No"}
                        </span>
                      </div>
                      <div class="ipqs-item">
                        <span class="label">Spam:</span>
                        <span class="value">
                          {ipqsData.threats?.spamming ? "Sí" : "No"}
                        </span>
                      </div>
                      <div class="ipqs-item">
                        <span class="label">Contenido adulto:</span>
                        <span class="value">
                          {ipqsData.threats?.adult ? "Sí" : "No"}
                        </span>
                      </div>
                    </div>
                  {:else}
                    <p class="muted small">
                      Pulsa “Ver detalles” para explorar todas las banderas que
                      IPQS detectó.
                    </p>
                  {/if}
                {:else}
                  <p class="muted small">
                    Todavía no hay reporte IPQS guardado para este dominio.
                  </p>
                {/if}
              </div>
            </div>
          </div>
        </section>

        <!-- STATS GLOBALES -->
        <section class="section-card stats-section">
          <div class="stats-grid">
            <!-- PÁGINAS ANALIZADAS (anillo neón) -->
            <div class="card pages-card">
              <div class="card-title"><h2> Historial General </h2></div>

              <div class="pages-text">
                <!-- <div class="muted small">
                    Historial total desde la instalación de la extensión.
                  </div> -->
                <div class="pages-bars">
                  <!-- SEGURAS -->
                  <div class="pages-bar-label">Seguras</div>
                  <div class="pages-bar-track">
                    <div
                      class="pages-bar-fill safe"
                      style={`width: ${
                        totalPages ? (safePages / totalPages) * 100 : 0
                      }%;`}
                    ></div>
                  </div>
                  <!-- BAJO RIESGO -->
                  <div class="pages-bar-label">Bajo Riesgo</div>
                  <div class="pages-bar-track">
                    <div
                      class="pages-bar-fill slow"
                      style={`width: ${
                        totalPages ? (lowRiskPages / totalPages) * 100 : 0
                      }%;`}
                    ></div>
                  </div>
                  <!-- MODERADO -->
                  <div class="pages-bar-label">Moderado</div>
                  <div class="pages-bar-track">
                    <div
                      class="pages-bar-fill moderate"
                      style={`width: ${
                        totalPages ? (mediumRiskPages / totalPages) * 100 : 0
                      }%;`}
                    ></div>
                  </div>

                  <!-- RIESGO ALTO -->
                  <div class="pages-bar-label">Riesgosas</div>
                  <div class="pages-bar-track">
                    <div
                      class="pages-bar-fill risky"
                      style={`width: ${
                        totalPages ? (highRiskPages / totalPages) * 100 : 0
                      }%;`}
                    ></div>
                  </div>
                </div>
              </div>
            </div>

            <!-- RESUMEN RIESGO GLOBAL (donut neón) -->
            <div class="card">
              <!-- <div class="card-title">Resumen de riesgo global</div> -->
               
               
              <div class="risk-pie-wrapper">
                <div
                  class="risk-pie"
                  style={`--safe:${globalRiskTotal ? (safePages / globalRiskTotal) * 100 : 0}; --low:${
                    globalRiskTotal ? (lowRiskPages / globalRiskTotal) * 100 : 0
                  }; --med:${
                    globalRiskTotal
                      ? (mediumRiskPages / globalRiskTotal) * 100
                      : 0
                  }; --high:${
                    globalRiskTotal
                      ? (highRiskPages / globalRiskTotal) * 100
                      : 0
                  };`}
                >
                  <div class="risk-pie-inner">
                    <span class="big-number tiny">{globalRiskTotal}</span>
                    <span class="muted tiny">dominios</span>
                  </div>
                </div>
                <ul class="risk-legend">
                  <li><span class="dot safe"></span>Seguro ({safePages})</li>
                  <li>
                    <span class="dot low"></span>Bajo riesgo ({lowRiskPages})
                  </li>
                  <li>
                    <span class="dot med"></span>Moderado ({mediumRiskPages})
                  </li>
                  <li><span class="dot high"></span>Alto ({highRiskPages})</li>
                </ul>
              </div>
            </div>

            <!-- ÚLTIMOS ANÁLISIS -->
            <div class="card">
              <div class="card-title">Últimos análisis</div>
              {#if recentPages && recentPages.length > 0}
                <ul class="recent-list">
                  {#each recentPages as p (p.url)}
                    <li>
                      <div class="primary">{p.url}</div>
                      <div class="secondary">
                        Score CybFox: {formatScore(p.currentScore)}
                      </div>
                    </li>
                  {/each}
                </ul>
              {:else}
                <p class="muted small">Todavía no hay historial de análisis.</p>
              {/if}
            </div>
          </div>
        </section>

        <!-- LISTAS -->
        <section class="lists-grid">
          <!-- BLOQUEADOS -->
          <div class="section-card">
            <div class="section-header spaced">
              <div>
                <h2>Lista de bloqueados</h2>
                <p class="subtitle small">
                  Dominios que serán bloqueados automáticamente.
                </p>
              </div>
              <span class="badge-neon small">
                Bloqueo forzado por el usuario
              </span>
            </div>

            <div class="search-row">
              <input
                class="input"
                placeholder="Buscar en lista de bloqueados..."
                bind:value={blacklistSearch}
              />
            </div>

            <div class="list-input-row">
              <input
                class="input"
                placeholder="https://dominio-peligroso.com"
                bind:value={blacklistInput}
              />
              <button
                class="btn-primary"
                on:click={() => toggleBlacklistUrl(blacklistInput)}
                disabled={togglingBlacklist}
              >
                Añadir
              </button>
            </div>

            <div class="simple-list scrollable">
              {#if filteredBlacklist && filteredBlacklist.length > 0}
                {#each filteredBlacklist as item (item.url)}
                  <div class="simple-list-item">
                    <div class="primary">{item.url}</div>
                    <div class="secondary">
                      Añadido: {formatDate(item.blacklistedAt)}
                    </div>
                    <button
                      class="pill danger"
                      on:click={() => toggleBlacklistUrl(item.url)}
                    >
                      Quitar
                    </button>
                  </div>
                {/each}
              {:else}
                <p class="muted small">
                  No tienes dominios bloqueados manualmente.
                </p>
              {/if}
            </div>
          </div>

          <!-- WHITELIST -->
          <div class="section-card">
            <div class="section-header spaced">
              <div>
                <h2>Lista blanca</h2>
                <p class="subtitle small">
                  Sitios de confianza que no serán bloqueados automáticamente.
                </p>
              </div>
              <span class="badge-neon small"> Sitios de confianza </span>
            </div>

            <div class="search-row">
              <input
                class="input"
                placeholder="Buscar en lista blanca..."
                bind:value={whitelistSearch}
              />
            </div>

            <div class="list-input-row">
              <input
                class="input"
                placeholder="https://sitio-confiable.com"
                bind:value={whitelistInput}
              />
              <button
                class="btn-primary"
                on:click={() => toggleWhitelistUrl(whitelistInput)}
                disabled={togglingWhitelist}
              >
                Añadir
              </button>
            </div>

            <div class="simple-list scrollable">
              {#if filteredWhitelist && filteredWhitelist.length > 0}
                {#each filteredWhitelist as item (item.url)}
                  <div class="simple-list-item">
                    <div class="primary">{item.url}</div>
                    <div class="secondary">
                      Añadido: {formatDate(item.whitelistedAt)}
                    </div>
                    <button
                      class="pill danger"
                      on:click={() => toggleWhitelistUrl(item.url)}
                    >
                      Quitar
                    </button>
                  </div>
                {/each}
              {:else}
                <p class="muted small">
                  Todavía no tienes sitios en la lista blanca.
                </p>
              {/if}
            </div>
          </div>
        </section>

        {#if toggleMessage}
          <div class="error-banner slim">
            {toggleMessage}
          </div>
        {/if}
      {/if}
    </main>
  </div>
</div>

<style>
  :global(html[data-theme="dark"] body) {
    background: radial-gradient(
      circle at top,
      #0b1120 0,
      #020617 45%,
      #000 100%
    );
    color: #e5e7eb;
  }

  :global(html[data-theme="light"] body) {
    background: linear-gradient(135deg, #e0f2fe, #f4f4f5);
    color: #0f172a;
  }

  .dashboard-root {
    min-height: 100vh;
    padding: 16px;
    box-sizing: border-box;
    font-family:
      system-ui,
      -apple-system,
      BlinkMacSystemFont,
      "SF Pro Text",
      "Segoe UI",
      sans-serif;
    font-size: 14px;
  }

  .layout {
    display: grid;
    grid-template-columns: 260px minmax(0, 1fr);
    gap: 20px;
    max-width: 1400px;
    margin: 0 auto;
  }

  /* SIDEBAR */
  .side-nav {
    background: rgba(15, 23, 42, 0.88);
    border-radius: 24px;
    padding: 20px 18px;
    border: 1px solid rgba(148, 163, 184, 0.45);
    box-shadow: 0 14px 45px rgba(15, 23, 42, 0.75);
    backdrop-filter: blur(24px);
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  .logo-block {
    display: flex;
    align-items: center;
    gap: 12px;
  }

 
  .logo-text {
    display: flex;
    flex-direction: column;
    line-height: 1.1;
  }

  .logo-main {
    font-weight: 700;
    letter-spacing: 0.08em;
    font-size: 0.9rem;
    text-transform: uppercase;
  }

  .logo-sub {
    font-size: 0.75rem;
    opacity: 0.7;
  }

  .nav-links {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  /* .nav-group-title {
    margin-top: 10px;
    margin-bottom: 4px;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    opacity: 0.6;
  } */

  .nav-item {
    border: none;
    background: transparent;
    padding: 8px 10px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    cursor: pointer;
    color: inherit;
    font-size: 0.86rem;
    transition:
      background 0.18s ease,
      transform 0.1s ease;
  }

  .nav-dot {
    width: 6px;
    height: 6px;
    border-radius: 999px;
    background: rgba(148, 163, 184, 0.6);
  }

  .nav-item:hover {
    background: radial-gradient(
      circle at 0% 0%,
      rgba(56, 189, 248, 0.35),
      transparent
    );
    transform: translateY(-1px);
  }

  .nav-item.active {
    background: linear-gradient(
      135deg,
      rgba(59, 130, 246, 0.32),
      rgba(37, 99, 235, 0.12)
    );
    box-shadow:
      0 0 0 1px rgba(59, 130, 246, 0.6),
      0 10px 30px rgba(15, 23, 42, 0.9);
  }

  .nav-item.active .nav-dot {
    background: #38bdf8;
  }

  /* MAIN */
  .main-area {
    display: flex;
    flex-direction: column;
    gap: 18px;
  }

  .top-bar {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
  }

  .top-left h1 {
    margin: 0 0 4px;
    font-size: 1.4rem;
  }

  .subtitle {
    margin: 0;
    font-size: 0.86rem;
    opacity: 0.75;
  }

  .subtitle.small {
    font-size: 0.78rem;
  }

  .top-controls {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .icon-btn {
    border: none;
    border-radius: 999px;
    padding: 6px 10px;
    background: rgba(30, 64, 175, 1);
    color: #e5e7eb;
    box-shadow: 0 0 18px rgba(59, 130, 246, 0.9);
    cursor: pointer;
    font-size: 0.9rem;
    transition:
      transform 0.1s ease,
      box-shadow 0.16s ease,
      background 0.16s ease;
  }

  .icon-btn:hover {
    transform: translateY(-1px);
    box-shadow: 0 0 28px rgba(56, 189, 248, 0.9);
    background: rgba(37, 99, 235, 1);
  }

  .section-card {
    background: rgba(15, 23, 42, 0.78);
    border-radius: 24px;
    padding: 18px 18px 20px;
    border: 1px solid rgba(148, 163, 184, 0.35);
    box-shadow: 0 18px 35px rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(24px);
  }

  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
    margin-bottom: 14px;
  }

  .section-header.spaced {
    align-items: center;
    margin-bottom: 16px;
  }

  .section-header h2 {
    margin: 0 0 2px;
    font-size: 1.05rem;
  }

  .section-subheader {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-bottom: 8px;
  }

  .section-subheader.row {
    flex-direction: row;
    align-items: center;
    justify-content: space-between;
  }

  .section-subheader h3 {
    margin: 0;
    font-size: 0.95rem;
  }

  .small-link {
    border: none;
    background: none;
    color: #60a5fa;
    font-size: 0.8rem;
    cursor: pointer;
    padding: 0;
  }

  .badge-neon {
    border-radius: 999px;
    padding: 4px 10px;
    font-size: 0.78rem;
    background: radial-gradient(
      circle at 0% 0%,
      rgba(59, 130, 246, 0.6),
      rgba(15, 23, 42, 0.9)
    );
    border: 1px solid rgba(96, 165, 250, 0.8);
    box-shadow: 0 0 22px rgba(59, 130, 246, 0.9);
    white-space: nowrap;
  }

  .badge-neon.small {
    font-size: 0.76rem;
    padding: 3px 9px;
  }

  .muted {
    opacity: 0.7;
  }

  .muted.small {
    font-size: 0.78rem;
  }

  .muted.tiny {
    font-size: 0.7rem;
  }

  .page-analyzed {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .current-url {
    margin-top: 20px;
    font-family: "SF Mono", ui-monospace, Menlo, Consolas, monospace;
    font-size: 0.85rem;
    padding: 6px 10px;
    border-radius: 999px;
    background: rgba(15, 23, 42, 0.96);
    border: 1px solid rgba(51, 65, 85, 0.9);
    max-width: 520px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .risk-summary {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 8px;
  }

  /* SEMÁFORO HORIZONTAL */
  .traffic-light {
    display: flex;
    flex-direction: row;
    gap: 10px;
    padding: 8px 10px;
    border-radius: 999px;
    background: radial-gradient(
      circle at 30% 0%,
      rgba(30, 64, 175, 0.85),
      rgba(15, 23, 42, 0.95)
    );
    border: 1px solid rgba(96, 165, 250, 0.75);
  }

  .light {
    width: 18px;
    height: 18px;
    border-radius: 999px;
    opacity: 0.25;
    transition:
      opacity 0.18s ease,
      box-shadow 0.18s ease,
      transform 0.1s ease;
  }

  .light-red {
    background: #ef4444;
  }

  .light-amber {
    background: #facc15;
  }

  .light-green {
    background: #22c55e;
  }

  .light.active {
    opacity: 1;
    box-shadow: 0 0 18px currentColor;
    transform: scale(1.05);
  }

  .page-grid {
    display: grid;
    grid-template-columns: minmax(0, 2.4fr) minmax(260px, 1.3fr);
    gap: 16px;
  }

  .page-main {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .page-side {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .card.mini {
    padding: 12px 12px 13px;
  }

  .score-grid {
    display: grid;
    grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr) minmax(0, 1.6fr);
    gap: 12px;
  }

  .score-ring-card {
    display: grid;
    grid-template-columns: 1.1fr minmax(0, 1.2fr);
    gap: 12px;
    align-items: center;
    padding: 12px 12px;
    border-radius: 18px;
    background: radial-gradient(
      circle at 0% 0%,
      rgba(59, 130, 246, 0.24),
      rgba(15, 23, 42, 0.98)
    );
    border: 1px solid rgba(147, 197, 253, 0.8);
  }

  .score-ring {
    width: 120px;
    height: 120px;
    border-radius: 999px;
    background: radial-gradient(
        circle at center,
        rgba(15, 23, 42, 1) 60%,
        transparent 61%
      ),
      conic-gradient(#38bdf8 calc(var(--pct, 0) * 1%), rgba(15, 23, 42, 0.85) 0);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 0 28px rgba(59, 130, 246, 0.85);
  }

  .score-ring-inner {
    width: 68%;
    height: 68%;
    border-radius: 999px;
    background: radial-gradient(circle at 30% 0%, #1e3a8a, #020617);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 2px;
  }

  .score-number {
    font-size: 1.5rem;
    font-weight: 600;
  }

  .score-number.small {
    font-size: 1.1rem;
  }

  .score-unit {
    font-size: 0.7rem;
    opacity: 0.7;
    margin-left: 2px;
  }

  .score-label {
    font-size: 0.75rem;
    opacity: 0.75;
  }

  .score-meta {
    font-size: 0.8rem;
  }

  .score-chip {
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    padding: 2px 10px;
    font-size: 0.74rem;
    border: 1px solid rgba(148, 163, 184, 0.7);
    margin-bottom: 4px;
  }

  .score-chip.ipqs {
    border-color: rgba(96, 165, 250, 0.9);
    color: #bfdbfe;
  }

  .score-chip.cybfox {
    border-color: rgba(45, 212, 191, 0.9);
    color: #a5f3fc;
  }

  .score-chip.vt {
    border-color: rgba(248, 113, 113, 0.9);
    color: #fecaca;
  }

  .score-card {
    padding: 10px 12px 12px;
    border-radius: 18px;
    background: radial-gradient(
      circle at 0% 0%,
      rgba(30, 64, 175, 0.35),
      rgba(15, 23, 42, 0.96)
    );
    border: 1px solid rgba(148, 163, 184, 0.7);
  }
  .score-card.virus-total-card {
    max-width: 250px; /* AJUSTA A TU GUSTO */
    width: 100%;
    justify-self: end;
  }

  .score-card.cybfox-card {
    max-width: 130px; /* AJUSTA A TU GUSTO */
    width: 100%;
  }

  .score-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 4px;
  }

  .score-title {
    font-size: 0.9rem;
    font-weight: 600;
  }

  .score-value-row {
    display: flex;
    align-items: baseline;
    gap: 2px;
    margin: 4px 0 2px;
    justify-content: center;
  }

  .score-value {
    font-size: 1.4rem;
    font-weight: 600;
  }

  .badge-row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 8px;
  }

  .tag-chip {
    border-radius: 999px;
    padding: 3px 9px;
    font-size: 0.74rem;
    background: rgba(30, 64, 175, 0.75);
    border: 1px solid rgba(96, 165, 250, 0.9);
  }

  .tag-chip.danger {
    background: rgba(185, 28, 28, 0.75);
    border-color: rgba(248, 113, 113, 0.95);
  }

  .tag-chip.success {
    background: rgba(22, 163, 74, 0.75);
    border-color: rgba(74, 222, 128, 0.95);
  }

  .tag-chip.ghost {
    background: rgba(15, 23, 42, 0.9);
    border-color: rgba(148, 163, 184, 0.9);
  }

  .evolution-card {
    padding: 10px 12px 4px;
    border-radius: 18px;
    background: rgba(15, 23, 42, 0.95);
    border: 1px solid rgba(55, 65, 81, 0.9);
  }

  .evo-row {
    display: grid;
    grid-template-columns: 140px minmax(0, 1fr) 44px;
    gap: 6px;
    align-items: center;
    margin: 4px 0;
  }

  .evo-date {
    font-size: 0.78rem;
    opacity: 0.8;
  }

  .evo-bar-wrap {
    height: 7px;
    border-radius: 999px;
    background: #020617;
    overflow: hidden;
    border: 1px solid rgba(30, 64, 175, 0.9);
  }

  .evo-bar {
    height: 100%;
    background: linear-gradient(90deg, #22d3ee, #0ea5e9, #f97316, #ef4444);
  }

  .evo-score {
    font-size: 0.8rem;
    text-align: right;
  }

  .simple-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: 0.8rem;
  }

  .simple-list .label {
    opacity: 0.7;
  }

  .simple-list .value {
    font-family: ui-monospace, Menlo, Consolas, monospace;
  }

  .tag-cloud {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .ipqs-details {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .ipqs-item {
    display: flex;
    justify-content: space-between;
    gap: 6px;
    font-size: 0.8rem;
  }

  .ipqs-item .label {
    opacity: 0.75;
  }

  .ipqs-item .value {
    font-family: ui-monospace, Menlo, Consolas, monospace;
  }

  /* VT DONUT MÁS VISUAL */
  .vt-chart {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 6px 0;
  }

  .vt-pie {
    width: 120px;
    height: 120px;
    border-radius: 999px;
    --total: calc(
      var(--h) + var(--m) + var(--s) + var(--u) + var(--t) + 0.0001
    );
    background: conic-gradient(
      #22c55e 0 calc((var(--h) / var(--total)) * 360deg),
      #ef4444 calc((var(--h) / var(--total)) * 360deg)
        calc(((var(--h) + var(--m)) / var(--total)) * 360deg),
      #f97316 calc(((var(--h) + var(--m)) / var(--total)) * 360deg)
        calc(((var(--h) + var(--m) + var(--s)) / var(--total)) * 360deg),
      #38bdf8 calc(((var(--h) + var(--m) + var(--s)) / var(--total)) * 360deg)
        calc(
          ((var(--h) + var(--m) + var(--s) + var(--u)) / var(--total)) * 360deg
        ),
      #6b7280
        calc(
          ((var(--h) + var(--m) + var(--s) + var(--u)) / var(--total)) * 360deg
        )
        360deg
    );
    position: relative;
    box-shadow: 0 0 24px rgba(59, 130, 246, 0.8);
  }

  .vt-pie-inner {
    position: absolute;
    inset: 12%;
    border-radius: 999px;
    background: radial-gradient(circle at 30% 0%, #020617, #0b1120);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
  }

  .vt-legend {
    list-style: none;
    padding: 0;
    margin: 0;
    font-size: 0.76rem;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .vt-legend .dot {
    width: 7px;
    height: 7px;
    border-radius: 999px;
    margin-right: 6px;
    display: inline-block;
  }

  .dot.harmless {
    background: #22c55e;
  }

  .dot.malicious {
    background: #ef4444;
  }

  .dot.suspicious {
    background: #f97316;
  }

  .dot.undetected {
    background: #38bdf8;
  }

  .stats-section {
    padding-top: 14px;
    padding-bottom: 16px;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
  }

  .card-title {
    font-size: 0.92rem;
    margin-bottom: 4px;
  }

  .big-number {
    font-size: 1.6rem;
    font-weight: 600;
    margin-bottom: 4px;
  }

  .big-number.tiny {
    font-size: 1rem;
  }

  /* CARD PÁGINAS ANALIZADAS */
  /* .pages-card-content {
    display: flex;
    align-items: center;
    gap: 12px;
  } */

  .pages-text {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .pages-bars {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 0.74rem;
  }

  .pages-bar-label {
    opacity: 0.7;
  }

  .pages-bar-track {
    height: 5px;
    border-radius: 999px;
    background: #020617;
    overflow: hidden;
  }

  .pages-bar-fill {
    height: 100%;
  }

  .pages-bar-fill.safe {
    background: linear-gradient(90deg, #4ade80, #169e48);
  }
  .pages-bar-fill.slow {
    background: linear-gradient(90deg, #60a5fa, #20508a);
  }
  .pages-bar-fill.moderate {
    background: linear-gradient(90deg, #eab308, #8e6b05);
  }

  .pages-bar-fill.risky {
    background: linear-gradient(90deg, #f97316, #ef4444);
  }

  .risk-pie-wrapper {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 60px; 
  }

  /* DONUT GLOBAL MÁS NEÓN */
  .risk-pie {
    --safe: 0;
    --low: 0;
    --med: 0;
    --high: 0;

    width: 130px;
    height: 130px;
    border-radius: 50%;
    position: relative; /* IMPORTANTE */

    background: conic-gradient(
      #4ade80 0 calc(var(--safe) * 1%),
      #38bdf8 calc(var(--safe) * 1%) calc((var(--safe) + var(--low)) * 1%),
      #facc15 calc((var(--safe) + var(--low)) * 1%)
        calc((var(--safe) + var(--low) + var(--med)) * 1%),
      #ef4444 calc((var(--safe) + var(--low) + var(--med)) * 1%)
        calc((var(--safe) + var(--low) + var(--med) + var(--high)) * 1%),
      #0f172a calc((var(--safe) + var(--low) + var(--med) + var(--high)) * 1%)
        100%
    );

    border: 4px solid transparent;
    background-clip: padding-box;
  }

  .risk-pie::before {
    content: "";
    position: absolute;
    inset: -4px;
    border-radius: inherit;
    background: linear-gradient(
      135deg,
      rgba(56, 189, 248, 0.9),
      rgba(59, 130, 246, 0.9),
      rgba(147, 51, 234, 0.9)
    );
    filter: blur(14px);
    z-index: -1; /* glow detrás del donut */
  }

  .risk-pie::after {
    content: "";
    position: absolute;
    inset: 12%;
    border-radius: 50%;
    background: radial-gradient(circle at 30% 30%, #0f172a, #000 70%);
    box-shadow: inset 0 0 25px rgba(59, 130, 246, 0.35);
    z-index: 0; /* detrás del texto, delante del donut */
  }

  .risk-pie-inner {
    position: absolute;
    top: 50%; /* <-- NUEVO */
    left: 50%; /* <-- NUEVO */
    transform: translate(-50%, -50%); /* <-- CENTRADO EXACTO */
    width: 20%; /* <-- AJUSTA EL TAMAÑO DEL HUECO */
    height: 52%;
    border-radius: 50%;

    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;

    z-index: 1;
    pointer-events: none;
  }
  .risk-legend {
    list-style: none;
    padding: 0;
    margin: 0;
    font-size: 0.78rem;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .risk-legend .dot {
    width: 7px;
    height: 7px;
    border-radius: 999px;
    margin-right: 6px;
    display: inline-block;
  }

  .dot.safe {
    background: #22c55e;
  }

  .dot.low {
    background: #38bdf8;
  }

  .dot.med {
    background: #eab308;
  }

  .dot.high {
    background: #ef4444;
  }

  .recent-list {
    list-style: none;
    padding: 0;
    margin: 0;
    font-size: 0.8rem;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .recent-list li {
    padding: 6px 8px;
    border-radius: 12px;
    background: rgba(15, 23, 42, 0.95);
    border: 1px solid rgba(30, 64, 175, 0.7);
  }

  .recent-list .primary {
    font-family: ui-monospace, Menlo, Consolas, monospace;
    font-size: 0.8rem;
  }

  .recent-list .secondary {
    font-size: 0.75rem;
    opacity: 0.75;
  }

  .lists-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px;
  }

  .search-row {
    display: flex;
    gap: 8px;
    margin-bottom: 8px;
  }

  .list-input-row {
    display: flex;
    gap: 8px;
    margin-bottom: 10px;
  }

  .input {
    flex: 1;
    border-radius: 999px;
    border: 1px solid rgba(51, 65, 85, 0.9);
    background: rgba(15, 23, 42, 0.95);
    padding: 7px 11px;
    color: inherit;
    font-size: 0.85rem;
    outline: none;
  }

  .input:focus {
    border-color: rgba(96, 165, 250, 0.95);
    box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.85);
  }

  .btn-primary {
    border: none;
    border-radius: 999px;
    padding: 7px 16px;
    background: linear-gradient(135deg, #38bdf8, #2563eb);
    color: #0b1120;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    box-shadow: 0 10px 25px rgba(37, 99, 235, 0.7);
  }

  .btn-primary:disabled {
    opacity: 0.6;
    cursor: default;
    box-shadow: none;
  }

  .btn-ghost {
    border-radius: 999px;
    border: 1px solid rgba(148, 163, 184, 0.7);
    background: transparent;
    padding: 5px 12px;
    font-size: 0.78rem;
    color: inherit;
    cursor: pointer;
    margin-top: 6px;
  }

  .btn-ghost.small {
    padding: 4px 10px;
  }

  .btn-ghost:disabled {
    opacity: 0.6;
    cursor: default;
  }

  .simple-list.scrollable {
    max-height: 220px;
    overflow: auto;
  }

  .simple-list-item {
    padding: 6px 8px;
    border-radius: 12px;
    background: rgba(15, 23, 42, 0.95);
    border: 1px solid rgba(30, 64, 175, 0.75);
    display: grid;
    grid-template-columns: minmax(0, 1.6fr) minmax(0, 1.2fr) auto;
    gap: 6px;
    align-items: center;
  }

  .simple-list-item .primary {
    font-family: ui-monospace, Menlo, Consolas, monospace;
    font-size: 0.8rem;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .simple-list-item .secondary {
    font-size: 0.75rem;
    opacity: 0.75;
  }

  .pill {
    border-radius: 999px;
    padding: 4px 10px;
    font-size: 0.78rem;
    border: none;
    cursor: pointer;
    white-space: nowrap;
  }

  .pill.danger {
    background: rgba(185, 28, 28, 0.9);
    color: #fee2e2;
  }

  .loading-state {
    margin-top: 60px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
    font-size: 0.9rem;
  }

  .spinner {
    width: 26px;
    height: 26px;
    border-radius: 999px;
    border: 3px solid rgba(148, 163, 184, 0.3);
    border-top-color: #38bdf8;
    animation: spin 0.7s linear infinite;
  }

  .error-banner {
    margin-top: 6px;
    margin-bottom: 4px;
    padding: 8px 10px;
    border-radius: 12px;
    background: rgba(185, 28, 28, 0.15);
    border: 1px solid rgba(248, 113, 113, 0.8);
    font-size: 0.8rem;
  }

  .error-banner.slim {
    margin-top: 8px;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  /* LIGHT THEME AJUSTES */

  /* LIGHT THEME AJUSTES (NUEVOS) */
  :global(html[data-theme="light"] body) {
    background: radial-gradient(
      circle at top,
      #e0f2fe 0,
      #f9fafb 45%,
      #ffffff 100%
    );
    color: #0f172a;
  }

  :global(html[data-theme="light"]) .section-card,
  :global(html[data-theme="light"]) .side-nav {
    background: rgba(255, 255, 255, 0.98);
    color: #0f172a;
    border-color: #e5e7eb;
    box-shadow: 0 10px 25px rgba(15, 23, 42, 0.08);
  }

  :global(html[data-theme="light"]) .score-ring-card,
  :global(html[data-theme="light"]) .score-card,
  :global(html[data-theme="light"]) .evolution-card,
  :global(html[data-theme="light"]) .card.mini,
  :global(html[data-theme="light"]) .recent-list li,
  :global(html[data-theme="light"]) .simple-list-item {
    background: #f9fafb;
    border-color: #e5e7eb;
  }

  :global(html[data-theme="light"]) .traffic-light {
    background: #e0f2fe;
    border-color: #bfdbfe;
  }

  :global(html[data-theme="light"]) .badge-neon {
    background: #e0f2fe;
    border-color: #93c5fd;
    box-shadow: none;
    color: #1e3a8a;
  }

  :global(html[data-theme="light"]) .current-url {
    background: #eff6ff;
    border-color: #bfdbfe;
    color: #0f172a;
  }

  :global(html[data-theme="light"]) .icon-btn {
    background: #e0f2fe;
    color: #0f172a;
    box-shadow: none;
  }

  :global(html[data-theme="light"]) .icon-btn:hover {
    box-shadow: 0 0 18px rgba(59, 130, 246, 0.3);
  }

  :global(html[data-theme="light"]) .input {
    background: #f9fafb;
    border-color: #e5e7eb;
    color: #0f172a;
  }

  :global(html[data-theme="light"]) .tag-chip {
    background: #e0f2fe;
    border-color: #93c5fd;
    color: #1e3a8a;
  }

  :global(html[data-theme="light"]) .pages-bar-track {
    background: #e5e7eb;
  }

  :global(html[data-theme="light"]) .risk-pie::after {
    background: radial-gradient(circle at 30% 30%, #e5e7eb, #f9fafb 70%);
    box-shadow: inset 0 0 18px rgba(148, 163, 184, 0.3);
  }

  :global(html[data-theme="light"]) .vt-pie-inner {
    background: radial-gradient(circle at 30% 0%, #e5e7eb, #f9fafb);
  }

  :global(html[data-theme="light"]) .muted {
    color: #6b7280;
    opacity: 1;
  }

  /* RESPONSIVE */
  @media (max-width: 1024px) {
    .layout {
      grid-template-columns: minmax(0, 1fr);
      max-width: 100%;
    }

    .dashboard-root {
      padding: 8px;
    }

    .side-nav {
      flex-direction: row;
      align-items: center;
      justify-content: space-between;
      padding: 12px 14px;
      position: sticky;
      top: 0;
      z-index: 10;
    }

    .nav-links {
      flex-direction: row;
      flex-wrap: nowrap;
      overflow-x: auto;
      scrollbar-width: none;
      gap: 4px;
    }

    .nav-links::-webkit-scrollbar {
      display: none;
    }

    .nav-item {
      padding: 6px 9px;
      font-size: 0.8rem;
      white-space: nowrap;
    }

    .current-url {
      max-width: 100%;
    }
  }

  @media (max-width: 900px) {
    .page-grid {
      grid-template-columns: minmax(0, 1fr);
    }

    .page-side {
      order: 2;
    }

    .page-main {
      order: 1;
    }

    .score-grid {
      grid-template-columns: minmax(0, 1fr);
    }

    .score-ring-card {
      grid-template-columns: minmax(0, 1fr);
      justify-items: center;
      text-align: center;
    }

    .score-ring {
      width: clamp(90px, 30vw, 120px);
      height: clamp(90px, 30vw, 120px);
      margin: 0 auto;
    }

    .vt-chart {
      flex-direction: column;
      align-items: center;
    }

    .vt-pie {
      width: clamp(90px, 30vw, 120px);
      height: clamp(90px, 30vw, 120px);
    }

    .stats-grid {
      grid-template-columns: minmax(0, 1fr);
    }

    .lists-grid {
      grid-template-columns: minmax(0, 1fr);
    }

    .risk-pie-wrapper {
      flex-direction: column;
      align-items: flex-start;
    }
  }

  @media (max-width: 640px) {
    .top-bar {
      flex-direction: column;
      align-items: flex-start;
      gap: 8px;
    }

    .section-card {
      padding: 12px 10px 14px;
      border-radius: 16px;
    }

    .page-analyzed {
      padding: 12px 10px 14px;
    }

    .simple-list-item {
      grid-template-columns: minmax(0, 1fr);
      align-items: flex-start;
    }

    .simple-list-item .secondary {
      text-align: left;
    }

    .score-card.virus-total-card {
      max-width: 100%;
    }

    .score-card.cybfox-card {
      max-width: 100%;
    }
  }
  /* ============================================================
   MODO CLARO — FIX VISUAL PARA LOS SCORE CARDS
   ============================================================ */
  :global(html[data-theme="light"]) .score-ring-card,
  :global(html[data-theme="light"]) .score-card,
  :global(html[data-theme="light"]) .evolution-card,
  :global(html[data-theme="light"]) .score-card.virus-total-card {
    background: #ffffff !important;
    border: 1px solid #d0d7e2 !important;
    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.06) !important;
  }

  /* RING DE IPQS EN MODO CLARO */
  :global(html[data-theme="light"]) .score-ring {
    background: radial-gradient(circle at center, #ffffff 60%, transparent 61%),
      conic-gradient(#3b82f6 calc(var(--pct, 0) * 1%), #e5e7eb 0);
    box-shadow: 0 0 10px rgba(59, 130, 246, 0.4);
  }

  :global(html[data-theme="light"]) .score-ring-inner {
    background: radial-gradient(circle at 30% 0%, #f0f6ff, #dbe7ff);
  }

  /* CYBFOX SCORE CARD */
  :global(html[data-theme="light"]) .cybfox-card {
    background: #ffffff !important;
    border-color: #cfe9e7 !important;
  }

  /* VIRUSTOTAL CHART */
  :global(html[data-theme="light"]) .vt-pie {
    box-shadow: 0 0 12px rgba(59, 130, 246, 0.4);
  }

  :global(html[data-theme="light"]) .vt-pie-inner {
    background: radial-gradient(circle at 30% 0%, #eef2ff, #e2e8f0);
  }

  /* BADGES */
  :global(html[data-theme="light"]) .score-chip,
  :global(html[data-theme="light"]) .tag-chip {
    background: #f1f5f9;
    border-color: #cbd5e1;
    color: #1e293b;
  }

  /* TEXTO */
  :global(html[data-theme="light"]) .score-label,
  :global(html[data-theme="light"]) .muted {
    color: #475569 !important;
    opacity: 1 !important;
  }

  /* BOTONES */
  :global(html[data-theme="light"]) .btn-ghost {
    border-color: #cbd5e1;
    color: #1e293b;
    background: #f8fafc;
  }

  :global(html[data-theme="light"]) .btn-ghost:hover {
    background: #e2e8f0;
  }

  /* IPQS + VT + CYBFOX HEADER LABELS */
  :global(html[data-theme="light"]) .score-title {
    color: #0f172a;
  }

  /* ============================
   ESTILOS DE BOTONES EN MODO CLARO
   ============================ */

  :global(html[data-theme="light"]) .btn-primary {
    background: linear-gradient(135deg, #60a5fa, #3b82f6);
    color: #ffffff;
    border: none;
    box-shadow: 0 6px 18px rgba(59, 130, 246, 0.45);
  }

  :global(html[data-theme="light"]) .btn-primary:hover {
    background: linear-gradient(135deg, #3b82f6, #1d4ed8);
    box-shadow: 0 0 18px rgba(96, 165, 250, 0.8);
  }

  :global(html[data-theme="light"]) .btn-ghost {
    background: rgba(224, 242, 254, 0.8);
    border-color: #93c5fd;
    color: #1e3a8a;
  }

  :global(html[data-theme="light"]) .btn-ghost:hover {
    background: rgba(191, 219, 254, 1);
  }

  :global(html[data-theme="light"]) .pill.danger {
    background: #ef4444;
    color: white;
  }

  :global(html[data-theme="light"]) .pill.danger:hover {
    background: #dc2626;
  }


  .logo-image {
  width: 60px;
  height: 60px;
  border-radius: 12px;
  overflow: hidden;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  box-shadow: 
    0 0 0 1px rgba(148, 163, 184, 0.35),
    0 0 18px rgba(56, 189, 248, 0.5);
}

.logo-image img {
  width: 100%;
  height: 100%;
  object-fit: contain;
}

</style>