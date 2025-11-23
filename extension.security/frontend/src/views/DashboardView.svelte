<script lang="ts">
  import ChatWrapper from "./ChatWrapper.svelte";
  import ChatButton from "./ChatButton.svelte";

  import { onMount } from "svelte";


    let showChat = false;

  const toggleChat = () => {
    showChat = !showChat;
  };

  const closeChat = () => {
    showChat = false;
  };

  // =================== TEMA (LIGHT / DARK) =====================
  let theme: "light" | "dark" = "dark";

  function toggleTheme() {
    theme = theme === "dark" ? "light" : "dark";
  }

  // =================== TIPOS =====================
  type HistoryPoint = {
    label: string;
    score: number;
  };

  type Threats = {
    phishing?: boolean;
    malware?: boolean;
    suspicious?: boolean;
    spam?: boolean;
    adult?: boolean;
  };

  type AnalyzedPage = {
    url: string;
    riskScore: number;
    level: string;
    tags: string[];
    timeAgo: string;
    autoBlocked: boolean;
    httpsOk: boolean;
    ipqsCategory: string;
    cybfoxScore: number;
    threats: Threats;
    history: HistoryPoint[];
  };

  // =================== DATOS MOCK (para luego conectar al backend) =====================

  // Resumen general
  let totalAnalizadas = 124;
  let totalRiesgosas = 37;
  let totalBloqueadasAuto = 21;
  let totalBlacklist = 15;
  let totalWhitelist = 9;

  // Distribución de riesgo
  const riskDistribution = [
    { label: "Seguro", value: 45 },
    { label: "Bajo riesgo", value: 28 },
    { label: "Moderado", value: 18 },
    { label: "Alto", value: 9 }
  ];

  // Últimos análisis (datos coherentes con lo que ya se ve)
  let recientes: AnalyzedPage[] = [
    {
      url: "https://banco-seguro.com",
      riskScore: 12,
      level: "Bajo riesgo",
      tags: ["HTTPS", "Login"],
      timeAgo: "hace 3 min",
      autoBlocked: false,
      httpsOk: true,
      ipqsCategory: "Finanzas / banca",
      cybfoxScore: 92,
      threats: {
        phishing: false,
        malware: false,
        suspicious: false,
        spam: false,
        adult: false
      },
      history: [
        { label: "Hace 3 días", score: 10 },
        { label: "Hace 1 día", score: 11 },
        { label: "Hoy", score: 12 }
      ]
    },
    {
      url: "http://micartera-premios.xyz",
      riskScore: 86,
      level: "Alto riesgo",
      tags: ["Posible estafa / scam", "Phishing"],
      timeAgo: "hace 15 min",
      autoBlocked: true,
      httpsOk: false,
      ipqsCategory: "Phishing / premios falsos",
      cybfoxScore: 18,
      threats: {
        phishing: true,
        malware: false,
        suspicious: true,
        spam: true
      },
      history: [
        { label: "Hace 3 días", score: 40 },
        { label: "Hace 1 día", score: 65 },
        { label: "Hoy", score: 86 }
      ]
    },
    {
      url: "https://plataforma-cursos.net",
      riskScore: 41,
      level: "Riesgo moderado",
      tags: ["Sospechoso / spam"],
      timeAgo: "hace 1 hora",
      autoBlocked: false,
      httpsOk: true,
      ipqsCategory: "Educación / publicidad agresiva",
      cybfoxScore: 63,
      threats: {
        phishing: false,
        malware: false,
        suspicious: true,
        spam: true
      },
      history: [
        { label: "Hace 3 días", score: 35 },
        { label: "Hace 1 día", score: 38 },
        { label: "Hoy", score: 41 }
      ]
    }
  ];

  // Página actualmente “analizada” (ligada al URL / query param)
  let currentPage: AnalyzedPage | null = null;

  // Listas de bloqueo / confianza
  type ListItem = {
    url: string;
    addedAt: string;
    reason?: string;
  };

  let blacklist: ListItem[] = [
    {
      url: "http://free-iphone-now.biz",
      addedAt: "2025-11-15",
      reason: "Sospecha de phishing"
    },
    {
      url: "http://crypto-magic-return.top",
      addedAt: "2025-11-14",
      reason: "Ofertas irreales"
    },
    {
      url: "http://adult-popups.ru",
      addedAt: "2025-11-10",
      reason: "Contenido adulto / popups"
    }
  ];

  let whitelist: ListItem[] = [
    {
      url: "https://uninorte.edu.co",
      addedAt: "2025-11-01",
      reason: "Sitio académico de confianza"
    },
    {
      url: "https://github.com",
      addedAt: "2025-11-03",
      reason: "Desarrollo"
    }
  ];

  // Buscadores / inputs
  let searchBlocked = "";
  let searchWhitelist = "";
  let newBlockedUrl = "";
  let newWhitelistUrl = "";

  // Filtros
  $: filteredBlacklist = blacklist.filter((item) =>
    item.url.toLowerCase().includes(searchBlocked.toLowerCase())
  );

  $: filteredWhitelist = whitelist.filter((item) =>
    item.url.toLowerCase().includes(searchWhitelist.toLowerCase())
  );

  // Acciones listas
  function addToBlacklist() {
    const url = newBlockedUrl.trim();
    if (!url) return;
    blacklist = [
      { url, addedAt: new Date().toISOString().slice(0, 10), reason: "Añadido manualmente" },
      ...blacklist
    ];
    newBlockedUrl = "";
    // TODO: llamar al backend para persistir
  }

  function removeFromBlacklist(url: string) {
    blacklist = blacklist.filter((item) => item.url !== url);
    // TODO: backend
  }

  function addToWhitelist() {
    const url = newWhitelistUrl.trim();
    if (!url) return;
    whitelist = [
      { url, addedAt: new Date().toISOString().slice(0, 10), reason: "Añadido manualmente" },
      ...whitelist
    ];
    newWhitelistUrl = "";
    // TODO: backend
  }

  function removeFromWhitelist(url: string) {
    whitelist = whitelist.filter((item) => item.url !== url);
    // TODO: backend
  }

  // =================== SEMÁFORO (derivado del riesgo) =====================

  $: trafficLevel =
    currentPage == null
      ? "desconocido"
      : currentPage.riskScore >= 70
      ? "alto"
      : currentPage.riskScore >= 35
      ? "medio"
      : "bajo";

  $: trafficText =
    trafficLevel === "alto"
      ? "Riesgo alto · Recomendado bloquear"
      : trafficLevel === "medio"
      ? "Riesgo moderado · Navega con precaución"
      : trafficLevel === "bajo"
      ? "Riesgo bajo · Sitio generalmente seguro"
      : "Aún sin datos suficientes";

  // =================== INIT / ONMOUNT =====================

onMount(async () => {
  try {
    const params = new URLSearchParams(window.location.search);
    const paramUrl = params.get("url");

    if (!paramUrl) {
      // Sin URL → usa mock
      currentPage = recientes[1];
      return;
    }

    // 👇 Llamada real al backend
    const res = await fetch(`http://localhost:3001/scan?url=${encodeURIComponent(paramUrl)}`, {
      method: "GET"
    });

    if (!res.ok) {
      console.error("Error backend:", res.status);
      // fallback con datos mock
      currentPage = { ...recientes[1], url: paramUrl };
      return;
    }

    const data = await res.json();

    // 👇 Mapear tu API → al formato que tu UI necesita
    currentPage = {
      url: data.url,
      riskScore: data.riskScore,
      level: data.level,
      tags: data.tags,
      timeAgo: "justo ahora",
      autoBlocked: data.autoBlocked,
      httpsOk: data.httpsOk,
      ipqsCategory: data.ipqsCategory,
      cybfoxScore: data.cybfoxScore,
      threats: data.threats,
      history: data.history
    };

  } catch (err) {
    console.error("Error DashboardView:", err);
    currentPage = recientes[1];
  }
});

</script>
<ChatButton toggle={toggleChat} />

<ChatWrapper open={showChat} close={closeChat} />

<main class={`dashboard ${theme}`}>
  <!-- ================= BARRA LATERAL ================= -->
  <aside class="sidebar">
    <div class="logo">
      <div class="logo-orb"></div>
      <div class="logo-text">
        <span class="logo-main">CybFox</span>
        <span class="logo-sub">Security Hub</span>
      </div>
    </div>

    <nav class="nav">
      <div class="nav-section-title">Panel</div>
      <button class="nav-item active">
        <span class="nav-pill"></span>
        <span>Resumen</span>
      </button>
      <button class="nav-item">
        <span class="nav-pill"></span>
        <span>Análisis profundo</span>
      </button>
      <button class="nav-item">
        <span class="nav-pill"></span>
        <span>Análisis rápido</span>
      </button>

      <div class="nav-section-title">Listas</div>
      <button class="nav-item">
        <span class="nav-pill"></span>
        <span>Lista de bloqueados</span>
      </button>
      <button class="nav-item">
        <span class="nav-pill"></span>
        <span>Lista blanca</span>
      </button>

      <div class="nav-section-title">Sistema</div>
      <button class="nav-item">
        <span class="nav-pill"></span>
        <span>Configuración</span>
      </button>
    </nav>

    <div class="sidebar-footer">
      <div class="sidebar-chip">
        <span class="status-dot"></span>
        Protección en tiempo real
      </div>
      <button class="theme-toggle" on:click={toggleTheme}>
        <span>{theme === "dark" ? "Modo claro" : "Modo oscuro"}</span>
        <div class="toggle-pill">
          <div class={`toggle-thumb ${theme}`}></div>
        </div>
      </button>
    </div>
  </aside>

  <!-- ================= CONTENIDO PRINCIPAL ================= -->
  <section class="content">
    <!-- HEADER SUPERIOR -->
    <header class="topbar">
      <div>
        <h1 class="page-title">Panel de seguridad</h1>
        <p class="page-subtitle">
          Vista general de tus análisis, bloqueos automáticos y listas personalizadas.
        </p>
      </div>
      <div class="top-actions">
        <button class="primary-btn">
          Escanear URL manualmente
        </button>
      </div>
    </header>

    <!-- PÁGINA ANALIZADA + SEMÁFORO -->
    {#if currentPage}
      <section class="panel current-page-panel neon-panel-soft">
        <div class="current-top">
          <div class="current-main">
            <div class="current-label">Página analizada</div>
            <div class="current-url">{currentPage.url}</div>
            <div class="current-meta-row">
              <span class="current-pill">
                Categoría IPQS: {currentPage.ipqsCategory}
              </span>
              <span class="current-pill">
                {currentPage.httpsOk ? "HTTPS activo" : "HTTP inseguro"}
              </span>
              <span class="current-pill">
                Score CybFox: {currentPage.cybfoxScore}/100
              </span>
              <span class="current-pill subtle">
                Último escaneo: {currentPage.timeAgo}
              </span>
            </div>
          </div>

          <div class="current-right">
            <div class="traffic-light">
              <div class="traffic-body">
                <div
                  class="traffic-dot green"
                  class:active={trafficLevel === "bajo"}
                ></div>
                <div
                  class="traffic-dot amber"
                  class:active={trafficLevel === "medio"}
                ></div>
                <div
                  class="traffic-dot red"
                  class:active={trafficLevel === "alto"}
                ></div>
              </div>
              <div class="traffic-text">{trafficText}</div>
            </div>

            <div class="current-score-box">
              <div class="current-score-label">Riesgo IPQS</div>
              <div class="current-score-value">
                {currentPage.riskScore}
                <span class="small">/100</span>
              </div>
              <div class="current-score-sub">
                {currentPage.level}
                {#if currentPage.autoBlocked}
                  · bloqueada automáticamente
                {/if}
              </div>
            </div>
          </div>
        </div>

        <div class="current-middle">
          <div class="current-tags">
            {#if currentPage.tags.length}
              {#each currentPage.tags as t}
                <span class="tag-chip">{t}</span>
              {/each}
            {:else}
              <span class="empty-text">Sin etiquetas de amenaza</span>
            {/if}
          </div>
          <div class="current-threats">
            <span class="threat-label">Amenazas detectadas:</span>
            {#if Object.values(currentPage.threats).some(Boolean)}
              {#if currentPage.threats.phishing}
                <span class="threat-chip danger">Phishing</span>
              {/if}
              {#if currentPage.threats.malware}
                <span class="threat-chip danger">Malware</span>
              {/if}
              {#if currentPage.threats.suspicious}
                <span class="threat-chip warn">Actividad sospechosa</span>
              {/if}
              {#if currentPage.threats.spam}
                <span class="threat-chip warn">Spam / publicidad agresiva</span>
              {/if}
              {#if currentPage.threats.adult}
                <span class="threat-chip warn">Contenido adulto</span>
              {/if}
            {:else}
              <span class="empty-text">No se reportan amenazas específicas.</span>
            {/if}
          </div>
        </div>

        <div class="current-history">
          <span class="history-title">Evolución del riesgo</span>
          <div class="history-bars">
            {#each currentPage.history as point}
              <div class="history-row">
                <span class="history-label">{point.label}</span>
                <div class="history-track">
                  <div
                    class="history-fill"
                    style={`width: ${point.score}%;`}
                  ></div>
                </div>
                <span class="history-score">{point.score}</span>
              </div>
            {/each}
          </div>
        </div>
      </section>
    {/if}

    <!-- TARJETAS RESUMEN -->
    <section class="grid-stats">
      <div class="stat-card">
        <div class="stat-label">Páginas analizadas</div>
        <div class="stat-value">{totalAnalizadas}</div>
        <div class="stat-footer">Histórico desde instalación</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Páginas riesgosas</div>
        <div class="stat-value">{totalRiesgosas}</div>
        <div class="stat-footer">
          {(Math.round((totalRiesgosas / totalAnalizadas) * 100) || 0)}% del total
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Bloqueos automáticos</div>
        <div class="stat-value">{totalBloqueadasAuto}</div>
        <div class="stat-footer">Basados en IPQS + reglas CybFox</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Listas personalizadas</div>
        <div class="stat-footer-row">
          <span>Blacklist: {totalBlacklist}</span>
          <span>Whitelist: {totalWhitelist}</span>
        </div>
      </div>
    </section>

    <!-- SECCIÓN CENTRAL: GRÁFICO + RECIENTES -->
    <section class="grid-main">
      <!-- Gráfico simple de distribución -->
      <div class="panel neon-panel">
        <div class="panel-header">
          <h2>Distribución de riesgo</h2>
          <span class="panel-tag">Últimas 24 horas</span>
        </div>
        <div class="chart-wrapper">
          {#each riskDistribution as item}
            <div class="chart-row">
              <div class="chart-label">{item.label}</div>
              <div class="chart-bar-track">
                <div
                  class="chart-bar-fill"
                  style={`width: ${item.value}%;`}
                ></div>
              </div>
              <div class="chart-value">{item.value}%</div>
            </div>
          {/each}
        </div>
      </div>

      <!-- Últimos análisis -->
      <div class="panel">
        <div class="panel-header">
          <h2>Últimos análisis</h2>
          <span class="panel-tag">Escaneos recientes</span>
        </div>
        <div class="recent-list">
          {#each recientes as item}
            <article class="recent-item">
              <div class="recent-main">
                <div class="recent-url">{item.url}</div>
                <div class="recent-meta">
                  <span class={`risk-pill ${item.autoBlocked ? "auto" : ""}`}>
                    {item.level}
                    {#if item.autoBlocked}
                      · bloqueada automáticamente
                    {/if}
                  </span>
                  <span class="recent-time">{item.timeAgo}</span>
                </div>
              </div>
              <div class="recent-side">
                <div class="recent-score">
                  {item.riskScore}
                  <span class="small">/100</span>
                </div>
                <div class="recent-tags">
                  {#each item.tags as t}
                    <span class="tag-chip">{t}</span>
                  {/each}
                </div>
              </div>
            </article>
          {/each}
        </div>
      </div>
    </section>

    <!-- LISTAS: BLACKLIST / WHITELIST -->
    <section class="grid-lists">
      <!-- BLACKLIST -->
      <div class="panel">
        <div class="panel-header">
          <h2>Lista de bloqueados</h2>
          <span class="panel-tag">Bloqueo forzado por el usuario</span>
        </div>

        <div class="list-controls">
          <input
            type="text"
            placeholder="Buscar en lista de bloqueados…"
            bind:value={searchBlocked}
          />
          <div class="add-row">
            <input
              type="text"
              placeholder="https://dominio-peligroso.com"
              bind:value={newBlockedUrl}
            />
            <button class="ghost-btn" on:click={addToBlacklist}>Añadir</button>
          </div>
        </div>

        <div class="list-table">
          {#if filteredBlacklist.length === 0}
            <p class="empty-text">No hay elementos en la lista con ese filtro.</p>
          {:else}
            {#each filteredBlacklist as item}
              <div class="list-row">
                <div class="list-main">
                  <div class="list-url">{item.url}</div>
                  <div class="list-meta">
                    <span>Añadido: {item.addedAt}</span>
                    {#if item.reason}
                      <span>· {item.reason}</span>
                    {/if}
                  </div>
                </div>
                <button
                  class="danger-btn"
                  on:click={() => removeFromBlacklist(item.url)}
                >
                  Quitar
                </button>
              </div>
            {/each}
          {/if}
        </div>
      </div>

      <!-- WHITELIST -->
      <div class="panel">
        <div class="panel-header">
          <h2>Lista blanca</h2>
          <span class="panel-tag">Sitios de confianza</span>
        </div>

        <div class="list-controls">
          <input
            type="text"
            placeholder="Buscar en lista blanca…"
            bind:value={searchWhitelist}
          />
          <div class="add-row">
            <input
              type="text"
              placeholder="https://sitio-confiable.com"
              bind:value={newWhitelistUrl}
            />
            <button class="ghost-btn" on:click={addToWhitelist}>Añadir</button>
          </div>
        </div>

        <div class="list-table">
          {#if filteredWhitelist.length === 0}
            <p class="empty-text">No hay elementos en la lista con ese filtro.</p>
          {:else}
            {#each filteredWhitelist as item}
              <div class="list-row">
                <div class="list-main">
                  <div class="list-url">{item.url}</div>
                  <div class="list-meta">
                    <span>Añadido: {item.addedAt}</span>
                    {#if item.reason}
                      <span>· {item.reason}</span>
                    {/if}
                  </div>
                </div>
                <button
                  class="danger-btn"
                  on:click={() => removeFromWhitelist(item.url)}
                >
                  Quitar
                </button>
              </div>
            {/each}
          {/if}
        </div>
      </div>
    </section>
  </section>
</main>

<style>
  :global(body) {
    margin: 0;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text",
      "Segoe UI", sans-serif;
  }

  .dashboard {
    display: grid;
    grid-template-columns: 260px minmax(0, 1fr);
    min-height: 100vh;
    transition: background 0.3s ease, color 0.3s ease;
  }

  /* ================= TEMAS ================= */
  .dashboard.dark {
    --bg-main: #020617;
    --bg-elevated: #020617;
    --bg-panel: #020617;
    --bg-panel-soft: #020617;
    --text-main: #e5f2ff;
    --text-soft: #9fb3c8;
    --border-subtle: rgba(148, 163, 184, 0.25);
    --neon: #38bdf8;
    --neon-soft: rgba(56, 189, 248, 0.25);
    --chip-bg: rgba(15, 23, 42, 0.9);
    --danger: #fb7185;
  }

  .dashboard.light {
    --bg-main: #edf3ff;
    --bg-elevated: #f9fbff;
    --bg-panel: #ffffff;
    --bg-panel-soft: #f1f5f9;
    --text-main: #0f172a;
    --text-soft: #64748b;
    --border-subtle: rgba(148, 163, 184, 0.4);
    --neon: #0ea5e9;
    --neon-soft: rgba(14, 165, 233, 0.18);
    --chip-bg: #e2f3ff;
    --danger: #e11d48;
  }

  /* SIDEBAR */
  .sidebar {
    background: radial-gradient(circle at top left, #0b1120, #020617 60%);
    border-right: 1px solid var(--border-subtle);
    padding: 1.4rem 1.2rem;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
    color: #e2e8f0;
  }

  .dashboard.light .sidebar {
    background: linear-gradient(180deg, #e0f2fe, #f8fafc 55%, #e5e7eb);
    color: #0f172a;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    margin-bottom: 0.6rem;
  }

  .logo-orb {
    width: 32px;
    height: 32px;
    border-radius: 999px;
    background: radial-gradient(circle at 30% 20%, #fbbf24, #f97316 40%, #0f172a);
    box-shadow: 0 0 18px rgba(56, 189, 248, 0.8);
  }

  .logo-text {
    display: flex;
    flex-direction: column;
  }

  .logo-main {
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-size: 0.9rem;
  }

  .logo-sub {
    font-size: 0.75rem;
    opacity: 0.75;
  }

  .nav {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    margin-top: 0.3rem;
  }

  .nav-section-title {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: #94a3b8;
    margin: 0.4rem 0 0.2rem;
  }

  .dashboard.light .nav-section-title {
    color: #64748b;
  }

  .nav-item {
    border: none;
    outline: none;
    background: transparent;
    color: inherit;
    font: inherit;
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.45rem 0.5rem;
    border-radius: 999px;
    cursor: pointer;
    position: relative;
    transition: background 0.18s ease, color 0.18s ease, transform 0.12s ease;
  }

  .nav-item:hover {
    background: rgba(15, 23, 42, 0.55);
    transform: translateX(2px);
  }

  .dashboard.light .nav-item:hover {
    background: rgba(148, 163, 184, 0.25);
  }

  .nav-item.active {
    background: rgba(15, 23, 42, 0.85);
    box-shadow: 0 0 0 1px var(--neon-soft), 0 0 20px var(--neon-soft);
    color: #e2e8f0;
  }

  .dashboard.light .nav-item.active {
    background: #ffffff;
    color: #0f172a;
    box-shadow: 0 0 0 1px rgba(148, 163, 184, 0.35), 0 0 18px rgba(148, 163, 184, 0.25);
  }

  .nav-pill {
    width: 6px;
    height: 6px;
    border-radius: 999px;
    background: var(--neon);
    box-shadow: 0 0 10px var(--neon);
  }

  .sidebar-footer {
    margin-top: auto;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .sidebar-chip {
    font-size: 0.78rem;
    padding: 0.35rem 0.6rem;
    border-radius: 999px;
    background: rgba(15, 23, 42, 0.9);
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    border: 1px solid rgba(148, 163, 184, 0.5);
  }

  .dashboard.light .sidebar-chip {
    background: rgba(226, 232, 240, 0.95);
  }

  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 999px;
    background: #22c55e;
    box-shadow: 0 0 8px rgba(34, 197, 94, 0.9);
  }

  .theme-toggle {
    border-radius: 999px;
    padding: 0.35rem 0.6rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.6rem;
    font-size: 0.78rem;
    border: 1px solid rgba(148, 163, 184, 0.5);
    background: rgba(15, 23, 42, 0.85);
    color: inherit;
    cursor: pointer;
  }

  .dashboard.light .theme-toggle {
    background: rgba(248, 250, 252, 0.9);
  }

  .toggle-pill {
    width: 36px;
    height: 18px;
    border-radius: 999px;
    background: rgba(15, 23, 42, 0.7);
    position: relative;
  }

  .dashboard.light .toggle-pill {
    background: rgba(148, 163, 184, 0.4);
  }

  .toggle-thumb {
    position: absolute;
    top: 2px;
    width: 14px;
    height: 14px;
    border-radius: 999px;
    background: var(--neon);
    box-shadow: 0 0 12px var(--neon-soft);
    transition: transform 0.2s ease;
  }

  .toggle-thumb.dark {
    transform: translateX(2px);
  }

  .toggle-thumb.light {
    transform: translateX(20px);
  }

  /* CONTENIDO PRINCIPAL */
  .content {
    background: radial-gradient(circle at top, rgba(56, 189, 248, 0.12), transparent 40%),
      var(--bg-main);
    color: var(--text-main);
    padding: 1.5rem 1.8rem 2rem;
    display: flex;
    flex-direction: column;
    gap: 1.3rem;
  }

  .topbar {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
  }

  .page-title {
    font-size: 1.5rem;
    font-weight: 600;
    letter-spacing: 0.02em;
  }

  .page-subtitle {
    margin: 0.25rem 0 0;
    font-size: 0.88rem;
    color: var(--text-soft);
  }

  .top-actions {
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  .primary-btn {
    border: none;
    outline: none;
    border-radius: 999px;
    padding: 0.5rem 1.1rem;
    font-size: 0.85rem;
    font-weight: 500;
    cursor: pointer;
    background: radial-gradient(circle at top, #38bdf8, #0f172a);
    color: white;
    box-shadow: 0 0 22px rgba(56, 189, 248, 0.5);
  }

  /* TARJETAS RESUMEN */
  .grid-stats {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.9rem;
  }

  .stat-card {
    background: radial-gradient(circle at top left, var(--neon-soft), var(--bg-panel));
    border-radius: 1rem;
    padding: 0.9rem 1rem;
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .stat-label {
    font-size: 0.8rem;
    color: var(--text-soft);
  }

  .stat-value {
    font-size: 1.6rem;
    font-weight: 600;
  }

  .stat-footer {
    font-size: 0.78rem;
    color: var(--text-soft);
    margin-top: 0.15rem;
  }

  .stat-footer-row {
    display: flex;
    justify-content: space-between;
    font-size: 0.8rem;
    color: var(--text-soft);
    margin-top: 0.3rem;
  }

  /* PANEL GENERAL */
  .panel {
    background: var(--bg-panel);
    border-radius: 1rem;
    padding: 1rem 1rem 0.9rem;
    border: 1px solid var(--border-subtle);
    box-shadow: 0 0 0 1px rgba(15, 23, 42, 0.12);
  }

  .neon-panel {
    box-shadow: 0 0 0 1px var(--neon-soft), 0 0 30px var(--neon-soft);
  }

  .neon-panel-soft {
    box-shadow: 0 0 0 1px var(--neon-soft), 0 0 16px var(--neon-soft);
  }

  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.7rem;
  }

  .panel-header h2 {
    font-size: 0.95rem;
    font-weight: 500;
  }

  .panel-tag {
    font-size: 0.7rem;
    padding: 0.2rem 0.45rem;
    border-radius: 999px;
    border: 1px solid var(--border-subtle);
    background: var(--chip-bg);
    color: var(--text-soft);
  }

  /* PÁGINA ANALIZADA */
  .current-page-panel {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .current-top {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
  }

  .current-main {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }

  .current-label {
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text-soft);
  }

  .current-url {
    font-size: 1.02rem;
    font-weight: 500;
    word-break: break-all;
  }

  .current-meta-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
  }

  .current-pill {
    font-size: 0.72rem;
    padding: 0.18rem 0.5rem;
    border-radius: 999px;
    border: 1px solid var(--border-subtle);
    background: var(--bg-panel-soft);
  }

  .current-pill.subtle {
    opacity: 0.8;
  }

  .current-right {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 0.5rem;
  }

  /* Semáforo */
  .traffic-light {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 0.3rem;
  }

  .traffic-body {
    display: flex;
    gap: 0.3rem;
    padding: 0.3rem 0.4rem;
    border-radius: 999px;
    background: rgba(15, 23, 42, 0.9);
  }

  .dashboard.light .traffic-body {
    background: rgba(15, 23, 42, 0.85);
  }

  .traffic-dot {
    width: 14px;
    height: 14px;
    border-radius: 999px;
    background: rgba(51, 65, 85, 0.9);
    opacity: 0.3;
  }

  .traffic-dot.green.active {
    background: #22c55e;
    opacity: 1;
    box-shadow: 0 0 12px rgba(34, 197, 94, 0.9);
  }

  .traffic-dot.amber.active {
    background: #fbbf24;
    opacity: 1;
    box-shadow: 0 0 12px rgba(251, 191, 36, 0.9);
  }

  .traffic-dot.red.active {
    background: #fb7185;
    opacity: 1;
    box-shadow: 0 0 12px rgba(248, 113, 113, 0.9);
  }

  .traffic-text {
    font-size: 0.78rem;
    color: var(--text-soft);
    max-width: 220px;
    text-align: right;
  }

  .current-score-box {
    text-align: right;
  }

  .current-score-label {
    font-size: 0.78rem;
    color: var(--text-soft);
  }

  .current-score-value {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono",
      "Courier New", monospace;
    font-size: 1.3rem;
    font-weight: 600;
  }

  .current-score-value .small {
    font-size: 0.7rem;
    color: var(--text-soft);
  }

  .current-score-sub {
    font-size: 0.78rem;
    color: var(--text-soft);
  }

  .current-middle {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
    align-items: flex-start;
  }

  .current-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
  }

  .current-threats {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
    align-items: center;
  }

  .threat-label {
    font-size: 0.78rem;
    color: var(--text-soft);
  }

  .threat-chip {
    font-size: 0.72rem;
    padding: 0.18rem 0.45rem;
    border-radius: 999px;
    border: 1px solid var(--border-subtle);
    background: var(--bg-panel-soft);
  }

  .threat-chip.danger {
    border-color: rgba(248, 113, 113, 0.7);
    background: rgba(248, 113, 113, 0.12);
  }

  .threat-chip.warn {
    border-color: rgba(234, 179, 8, 0.7);
    background: rgba(234, 179, 8, 0.12);
  }

  .current-history {
    margin-top: 0.3rem;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .history-title {
    font-size: 0.78rem;
    color: var(--text-soft);
  }

  .history-bars {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .history-row {
    display: grid;
    grid-template-columns: 90px minmax(0, 1fr) 38px;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.78rem;
  }

  .history-label {
    color: var(--text-soft);
  }

  .history-track {
    height: 6px;
    border-radius: 999px;
    background: rgba(15, 23, 42, 0.75);
    overflow: hidden;
  }

  .dashboard.light .history-track {
    background: rgba(148, 163, 184, 0.25);
  }

  .history-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--neon), #6366f1);
    box-shadow: 0 0 10px var(--neon-soft);
  }

  .history-score {
    text-align: right;
    color: var(--text-soft);
  }

  /* REUTILIZABLES */
  .tag-chip {
    font-size: 0.7rem;
    padding: 0.15rem 0.35rem;
    border-radius: 999px;
    background: var(--chip-bg);
  }

  .empty-text {
    font-size: 0.8rem;
    color: var(--text-soft);
  }

  /* GRID CENTRAL */
  .grid-main {
    display: grid;
    grid-template-columns: minmax(0, 1.2fr) minmax(0, 1.4fr);
    gap: 1rem;
    align-items: flex-start;
  }

  /* CHART */
  .chart-wrapper {
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
    margin-top: 0.2rem;
  }

  .chart-row {
    display: grid;
    grid-template-columns: 90px minmax(0, 1fr) 40px;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
  }

  .chart-label {
    color: var(--text-soft);
  }

  .chart-bar-track {
    height: 8px;
    border-radius: 999px;
    background: rgba(15, 23, 42, 0.75);
    overflow: hidden;
  }

  .dashboard.light .chart-bar-track {
    background: rgba(148, 163, 184, 0.25);
  }

  .chart-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--neon), #6366f1);
    box-shadow: 0 0 10px var(--neon-soft);
  }

  .chart-value {
    text-align: right;
    color: var(--text-soft);
  }

  /* RECIENTES */
  .recent-list {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    max-height: 230px;
    overflow: auto;
  }

  .recent-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.6rem;
    padding: 0.55rem 0.4rem;
    border-radius: 0.75rem;
    background: var(--bg-panel-soft);
  }

  .recent-main {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }

  .recent-url {
    font-size: 0.85rem;
    white-space: nowrap;
    text-overflow: ellipsis;
    overflow: hidden;
  }

  .recent-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
    align-items: center;
  }

  .recent-time {
    font-size: 0.75rem;
    color: var(--text-soft);
  }

  .risk-pill {
    font-size: 0.75rem;
    padding: 0.15rem 0.45rem;
    border-radius: 999px;
    border: 1px solid rgba(148, 163, 184, 0.5);
    background: rgba(15, 23, 42, 0.8);
  }

  .risk-pill.auto {
    border-color: var(--neon);
    box-shadow: 0 0 12px var(--neon-soft);
  }

  .recent-side {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 0.2rem;
  }

  .recent-score {
    font-family: "SF Mono", ui-monospace, Menlo, Monaco, Consolas, "Liberation Mono",
      "Courier New", monospace;
    font-size: 1rem;
  }

  .recent-score .small {
    font-size: 0.65rem;
    color: var(--text-soft);
  }

  .recent-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
    justify-content: flex-end;
  }

  /* LISTAS */
  .grid-lists {
    display: grid;
    grid-template-columns: minmax(0, 1.2fr) minmax(0, 1.2fr);
    gap: 1rem;
    margin-top: 0.2rem;
  }

  .list-controls {
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
    margin-bottom: 0.6rem;
  }

  .list-controls input[type="text"] {
    border-radius: 0.65rem;
    border: 1px solid var(--border-subtle);
    padding: 0.35rem 0.6rem;
    font-size: 0.8rem;
    background: var(--bg-panel-soft);
    color: var(--text-main);
  }

  .add-row {
    display: flex;
    gap: 0.4rem;
  }

  .add-row input {
    flex: 1;
  }

  .ghost-btn {
    border-radius: 0.65rem;
    border: 1px solid var(--neon);
    padding: 0.35rem 0.7rem;
    font-size: 0.8rem;
    background: transparent;
    color: var(--neon);
    cursor: pointer;
  }

  .list-table {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    max-height: 210px;
    overflow: auto;
  }

  .list-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.4rem;
    padding: 0.45rem 0.4rem;
    border-radius: 0.7rem;
    background: var(--bg-panel-soft);
  }

  .list-main {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }

  .list-url {
    font-size: 0.83rem;
    white-space: nowrap;
    text-overflow: ellipsis;
    overflow: hidden;
  }

  .list-meta {
    font-size: 0.74rem;
    color: var(--text-soft);
  }

  .danger-btn {
    border-radius: 999px;
    border: none;
    padding: 0.3rem 0.7rem;
    font-size: 0.75rem;
    background: rgba(248, 113, 113, 0.1);
    color: var(--danger);
    cursor: pointer;
  }

  @media (max-width: 1024px) {
    .dashboard {
      grid-template-columns: 230px minmax(0, 1fr);
    }

    .grid-stats {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .grid-main,
    .grid-lists {
      grid-template-columns: minmax(0, 1fr);
    }
  }

  @media (max-width: 768px) {
    .dashboard {
      grid-template-columns: 1fr;
    }

    .sidebar {
      display: none;
    }
  }
</style>
