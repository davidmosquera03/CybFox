<script>
  import { onMount } from "svelte";
  import logoPopup from "../assets/logo-popup.png";

  const DEFAULT_TAG_OPTIONS = [
    "Posible estafa / scam",
    "Riesgo de robo de datos",
    "Contenido adulto",
    "Sospechoso / spam",
    "Sitio confiable",
    "Otro contenido no deseado",
  ];

  const TAG_KEY_PREFIX = "cybfox-tags:";
  const PIE_RADIUS = 28;
  const PIE_CIRC = 2 * Math.PI * PIE_RADIUS;

  let currentUrl = "";
  let domain = "";

  // loading
  let loadingAuto = true;
  let loadingIpqs = false;
  let loadingCrt = false;

  // errores / mensajes
  let autoError = "";
  let ipqsError = "";
  let crtError = "";
  let testMessage = "";

  // ===== SCORE PRINCIPAL (VT solo) =====
  // vtRiskPercent = 0–100 (0 = sin riesgo, 100 = muy riesgoso)
  let vtRiskPercent = null;
  let riskBadgeClass = "risk-unknown";
  let pieClass = "pie-unknown";
  let riskLabel = "DESCONOCIDO";
  let categoryText = "Sin información suficiente";
  let mainStrokeDasharray = `0 ${PIE_CIRC}`;

  // datos extra
  let cybfoxScore = null; // currentScore desde meta:domain (0 malo – 100 bueno)
  let vtBadEngines = null; // malicious + suspicious
  let vtTotalEngines = null;

  // ===== IPQS (manual) =====
  let ipqsSafePercent = null;
  let ipqsPieClass = "pie-unknown";
  let ipqsRiskBadgeClass = "risk-unknown";
  let ipqsRiskLabel = "Desconocido";
  let ipqsStrokeDasharray = `0 ${PIE_CIRC}`;
  let ipqsScore = null; // 0 (seguro) – 100 (muy riesgoso)

  // ===== CRT (manual) =====
  let crtRiskLabel = "Desconocido";
  let crtRiskBadgeClass = "risk-unknown";
  let crtStatusText = "";
  let crtIssuer = "";
  let crtValidTo = "";

  // ===== TAGS (localStorage) =====
  let tags = [];
  let selectedDefaultTag = "";

  // ================= UTILS =================

  function getStorageKey(url) {
    try {
      const host = new URL(url).hostname;
      return TAG_KEY_PREFIX + host;
    } catch {
      return TAG_KEY_PREFIX + url;
    }
  }

  function loadTags() {
    if (!currentUrl) return;
    const key = getStorageKey(currentUrl);
    const raw = localStorage.getItem(key);
    try {
      tags = raw ? JSON.parse(raw) : [];
    } catch {
      tags = [];
    }
  }

const API_BASE = "http://localhost:3000/api";

// tags debe ser tu array de strings, ej: ["Sospechoso / spam", "Phishing"]
async function saveTags() {
  if (!currentUrl) return;

  // 1) Sigue guardando en localStorage (para que el popup recuerde la selección del usuario)
  const key = getStorageKey(currentUrl);
  localStorage.setItem(key, JSON.stringify(tags));

  // 2) Además guardar en la BD para que el Dashboard lo lea
  try {
    const res = await fetch("http://localhost:3000/api/db/set-tags", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: currentUrl,  // URL o dominio, backend extrae dominio
        tags,             // el array completo: ["Sospechoso", "Phishing"]
      }),
    });

    const json = await res.json();
    if (!res.ok || !json.success) {
      console.warn("[CybFox] No se pudieron guardar tags en backend:", json);
    } else {
      console.log("[CybFox] Etiquetas guardadas correctamente:", json.tags);
    }
  } catch (err) {
    console.error("[CybFox] Error llamando a /db/set-tags:", err);
  }
}


  function chipClass(label) {
    const lower = label.toLowerCase();
    if (
      lower.includes("estafa") ||
      lower.includes("scam") ||
      lower.includes("robo")
    ) {
      return "chip-danger";
    }
    if (
      lower.includes("adult") ||
      lower.includes("spam") ||
      lower.includes("sospech")
    ) {
      return "chip-warn";
    }
    if (lower.includes("confiable") || lower.includes("seguro")) {
      return "chip-safe";
    }
    return "chip-info";
  }

  function addSelectedTag() {
    if (!selectedDefaultTag) return;
    if (!tags.includes(selectedDefaultTag)) {
      tags = [...tags, selectedDefaultTag];
      saveTags();
    }
    selectedDefaultTag = "";
  }

  function removeTag(tagToRemove) {
    tags = tags.filter((t) => t !== tagToRemove);
    saveTags();
  }

  function normalizeSafePercent(v) {
    if (v == null || Number.isNaN(v)) return null;
    return Math.max(0, Math.min(100, v));
  }

  // IPQS usa “safePercent” clásico (0–100 seguro)
  function computeRiskMetaFromSafe(safe) {
    if (safe == null) {
      return {
        label: "DESCONOCIDO",
        badgeClass: "risk-unknown",
        pieClass: "pie-unknown",
        category: "Sin información suficiente",
      };
    }
    const risk = 100 - safe;

    if (risk <= 20) {
      return {
        label: "SEGURO",
        badgeClass: "risk-safe",
        pieClass: "pie-safe",
        category: "Probablemente legítimo",
      };
    }
    if (risk <= 50) {
      return {
        label: "ADVERTENCIA",
        badgeClass: "risk-warn",
        pieClass: "pie-warn",
        category: "Sitio con señales mixtas",
      };
    }
    return {
      label: "PELIGROSO",
      badgeClass: "risk-danger",
      pieClass: "pie-danger",
      category: "Sitio potencialmente riesgoso",
    };
  }

  // VirusTotal: clasifica según cuántos motores marcan malicioso/sospechoso
  function computeVtMetaFromCounts(bad, total) {
    if (bad == null || total == null || total === 0) {
      return {
        label: "DESCONOCIDO",
        badgeClass: "risk-unknown",
        pieClass: "pie-unknown",
        category: "Sin información suficiente",
      };
    }

    if (bad === 0) {
      return {
        label: "SEGURO",
        badgeClass: "risk-safe",
        pieClass: "pie-safe",
        category:
          "Sin detecciones: ningún motor marca la URL como maliciosa o sospechosa.",
      };
    }

    const ratio = (bad / total) * 100; // porcentaje de motores que la ven maliciosa

    // 1–2 motores → advertencia (amarillo)
    if (bad <= 2) {
      return {
        label: "ADVERTENCIA",
        badgeClass: "risk-warn",
        pieClass: "pie-warn",
        category:
          "Uno o pocos motores de seguridad marcan esta URL como sospechosa. Recomendado navegar con precaución.",
      };
    }

    // 3–10 motores (o hasta ~15 %) → peligroso
    if (bad <= 10 || ratio <= 15) {
      return {
        label: "PELIGROSO",
        badgeClass: "risk-danger",
        pieClass: "pie-danger",
        category:
          "Varios motores detectan esta URL como maliciosa o sospechosa. Es mejor no introducir datos sensibles.",
      };
    }

    // >10 motores (~>15 %) → crítico (ej. 17/98)
    return {
      label: "CRÍTICO",
      badgeClass: "risk-danger",
      pieClass: "pie-danger",
      category:
        "Muchos motores de seguridad consideran esta URL maliciosa. Se recomienda NO continuar ni introducir datos.",
    };
  }

  async function safeJSON(res) {
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  }

  function copyUrl() {
    if (!currentUrl || !navigator.clipboard) return;
    navigator.clipboard.writeText(currentUrl).catch(() => {});
  }

  function openDashboard() {
    try {
      if (typeof chrome !== "undefined" && chrome.runtime) {
        const encoded = encodeURIComponent(currentUrl || "");

        const basePath = "frontend/dist/index.html?view=dashboard";
        const finalPath = encoded ? `${basePath}&url=${encoded}` : basePath;

        const url = chrome.runtime.getURL(finalPath);

        chrome.tabs.create({ url });
      }
    } catch (e) {
      console.error("No se pudo abrir el dashboard", e);
    }
  }

  // ================= BACKEND CALLS =================

  // VT SOLO (la dona principal, muestra riesgo)
  async function runAutoAnalysis(url) {
    if (!url) return;
    loadingAuto = true;
    autoError = "";
    vtRiskPercent = null;
    vtBadEngines = null;
    vtTotalEngines = null;
    mainStrokeDasharray = `0 ${PIE_CIRC}`;

    try {
      const vt = await fetch(
        `http://localhost:3000/api/check-vt?url=${encodeURIComponent(url)}`,
      ).then(safeJSON);

      if (vt && vt.success && vt.stats) {
        const {
          malicious = 0,
          suspicious = 0,
          undetected = 0,
          harmless = 0,
        } = vt.stats;

        const total = malicious + suspicious + undetected + harmless;
        const bad = malicious + suspicious;

        if (total > 0) {
          vtBadEngines = bad;
          vtTotalEngines = total;

          // Riesgo base: % de motores que lo ven malicioso/sospechoso
          const baseRisk = (bad / total) * 100; // 0–100

          // Amplificamos para que 17/98 se vea claramente alto
          const visualRisk = Math.min(100, baseRisk * 3);
          vtRiskPercent = normalizeSafePercent(visualRisk);
        } else {
          vtRiskPercent = null;
        }

        const meta = computeVtMetaFromCounts(vtBadEngines, vtTotalEngines);
        riskLabel = meta.label;
        riskBadgeClass = meta.badgeClass;
        pieClass = meta.pieClass;
        categoryText = meta.category;
      } else if (vt && vt.success === false) {
        autoError =
          vt.message ||
          (vt.error && vt.error.message) ||
          "VirusTotal no pudo analizar la URL.";
        vtRiskPercent = null;
        const meta = computeVtMetaFromCounts(null, null);
        riskLabel = meta.label;
        riskBadgeClass = meta.badgeClass;
        pieClass = meta.pieClass;
        categoryText = meta.category;
      } else {
        vtRiskPercent = null;
        const meta = computeVtMetaFromCounts(null, null);
        riskLabel = meta.label;
        riskBadgeClass = meta.badgeClass;
        pieClass = meta.pieClass;
        categoryText = meta.category;
      }

      if (vtRiskPercent != null) {
        const dash = (vtRiskPercent / 100) * PIE_CIRC;
        mainStrokeDasharray = `${dash} ${PIE_CIRC}`;
      } else {
        mainStrokeDasharray = `0 ${PIE_CIRC}`;
      }
    } catch (e) {
      console.error(e);
      autoError = "No se pudo analizar la página automáticamente.";
      vtRiskPercent = null;
      const meta = computeVtMetaFromCounts(null, null);
      riskLabel = meta.label;
      riskBadgeClass = meta.badgeClass;
      pieClass = meta.pieClass;
      categoryText = meta.category;
      mainStrokeDasharray = `0 ${PIE_CIRC}`;
    } finally {
      loadingAuto = false;
    }
  }

  // IPQS (manual, misma lógica de antes)
  async function runIpqsScan() {
    if (!currentUrl || loadingIpqs) return;

    loadingIpqs = true;
    ipqsError = "";
    ipqsSafePercent = null;
    ipqsStrokeDasharray = `0 ${PIE_CIRC}`;
    ipqsScore = null;

    try {
      const res = await fetch(
        `http://localhost:3000/api/check-ipqs?url=${encodeURIComponent(
          currentUrl,
        )}`,
      ).then(safeJSON);

      const rawRisk = res?.fraud_score ?? res?.risk_score ?? res?.score ?? null; // 0 seguro – 100 muy riesgoso

      if (rawRisk == null) {
        ipqsError = "No se pudo obtener el score de IPQS.";
      } else {
        ipqsScore = normalizeSafePercent(rawRisk);
        const safe = normalizeSafePercent(100 - ipqsScore);
        ipqsSafePercent = safe;

        const meta = computeRiskMetaFromSafe(safe);
        ipqsRiskLabel = meta.label;
        ipqsRiskBadgeClass = meta.badgeClass;
        ipqsPieClass = meta.pieClass;

        if (safe != null) {
          const dash = (safe / 100) * PIE_CIRC;
          ipqsStrokeDasharray = `${dash} ${PIE_CIRC}`;
        }
      }
    } catch (e) {
      console.error(e);
      ipqsError = "Error al consultar IPQS.";
    } finally {
      loadingIpqs = false;
    }
  }

  // CRT (manual, usa ?domain=)
  async function runCrtScan() {
    if (!domain || loadingCrt) return;

    loadingCrt = true;
    crtError = "";
    crtStatusText = "";
    crtIssuer = "";
    crtValidTo = "";
    crtRiskLabel = "Desconocido";
    crtRiskBadgeClass = "risk-unknown";

    try {
      const res = await fetch(
        `http://localhost:3000/api/check-crt?domain=${encodeURIComponent(
          domain,
        )}`,
      ).then(safeJSON);

      if (!res || res.success === false) {
        crtError =
          res?.message || "No se pudo obtener información del certificado.";
        return;
      }

      const https = res.https === true;
      const domainMatch = res.domain_match === true;

      crtIssuer = res.issuer || "";
      crtValidTo = res.valid_from
        ? `${res.valid_from} → ${res.valid_to || ""}`
        : res.valid_to || "";

      if (!https) {
        crtRiskLabel = "Sin HTTPS";
        crtRiskBadgeClass = "risk-danger";
        crtStatusText =
          "El sitio no presenta un certificado HTTPS válido o está deshabilitado.";
      } else if (https && !domainMatch) {
        crtRiskLabel = "Dominio no coincide";
        crtRiskBadgeClass = "risk-warn";
        crtStatusText =
          "El certificado está activo, pero el dominio no coincide exactamente.";
      } else {
        crtRiskLabel = "Certificado válido";
        crtRiskBadgeClass = "risk-safe";
        crtStatusText = "El certificado SSL parece válido para este dominio.";
      }
    } catch (e) {
      console.error(e);
      crtError = "Error al consultar certificado SSL/CRT.";
    } finally {
      loadingCrt = false;
    }
  }

  // Test backend
  async function runTestApi() {
    testMessage = "";
    try {
      const res = await fetch("http://localhost:3000/api/test").then(safeJSON);
      testMessage = res?.message || "API OK";
    } catch (e) {
      console.error(e);
      testMessage = "Error al probar la API.";
    }
  }

  // ====== Cargar meta:domain.currentScore como hace blocked.js ======
  function loadMetaScore() {
    if (!domain || typeof chrome === "undefined" || !chrome.storage) return;

    chrome.storage.local.get([`meta:${domain}`], (raw) => {
      try {
        const meta = raw[`meta:${domain}`] || {};
        if (typeof meta.currentScore === "number") {
          const safe = Math.max(0, Math.min(100, meta.currentScore));
          cybfoxScore = safe;
        } else {
          cybfoxScore = null;
        }
      } catch (e) {
        console.error("[CybFox] Error leyendo meta en popup:", e);
      }
    });
  }

  // ================= ON MOUNT =================
  onMount(() => {
    try {
      if (typeof chrome !== "undefined" && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          const tab = tabs && tabs[0];
          let rawUrl = tab?.url || "";
          let finalUrl = rawUrl;

          try {
            const u = new URL(rawUrl);

            // si estoy en la página bloqueada de la extensión,
            // saco la URL original del query ?url=
            if (
              u.protocol === "chrome-extension:" &&
              u.searchParams.has("url")
            ) {
              const originalEncoded = u.searchParams.get("url");
              const original = originalEncoded
                ? decodeURIComponent(originalEncoded)
                : "";

              if (original) {
                finalUrl = original;
              }
            }
          } catch {
            // si no es una URL válida, usamos tal cual
          }

          // si llega solo dominio (enter.co) → https://enter.co
          if (finalUrl && !/^https?:\/\//i.test(finalUrl)) {
            finalUrl = "https://" + finalUrl;
          }

          currentUrl = finalUrl;

          try {
            domain = currentUrl ? new URL(currentUrl).hostname : "";
          } catch {
            domain = currentUrl || "";
          }

          loadTags();
          loadMetaScore(); // mismo currentScore que en blocked.js

          if (currentUrl) {
            runAutoAnalysis(currentUrl); // VT
          } else {
            loadingAuto = false;
          }
        });
      } else {
        loadingAuto = false;
      }
    } catch (e) {
      console.error(e);
      loadingAuto = false;
    }
  });
</script>

<div class="popup {loadingAuto || loadingIpqs || loadingCrt ? 'loading' : ''}">
  <!-- HEADER -->
<header class="header">
  <div class="logo-dot">
    <img src={logoPopup} alt="CybFox logo" class="logo-img" />
  </div>
  <div class="title-block">
    <h1>CybFox – Navegación segura</h1>
   
  </div>
</header>


  <!-- URL CARD 
  <section class="url-card">
    <div class="label">Sitio actual</div>
    <div class="url-text" title={currentUrl || "Sin URL"}>
      {#if currentUrl}
        {currentUrl}
      {:else}
        URL no disponible
      {/if}
    </div>
    <button class="secondary" on:click={copyUrl}>Copiar URL</button>
  </section> -->

  <!-- SCANNER -->
  <section class="scanner-section">
    <div class="scanner-frame">
      <div class="scanner-grid"></div>
      {#if loadingAuto || loadingIpqs || loadingCrt}
        <div class="scanner-line"></div>
      {/if}
      <div class="scanner-center">
        <span>
          {#if loadingAuto}
            Escaneando sitio…
          {:else if loadingIpqs}
            Ejecutando IPQS…
          {:else if loadingCrt}
            Revisando certificado…
          {:else}
            Análisis listo
          {/if}
        </span>
      </div>
    </div>
  </section>

  <!-- RESUMEN PRINCIPAL (VT + CybFoxScore textual) -->
  <section class="summary-card">
    <div class="summary-header">
      <span class="summary-title">Resumen rápido</span>
      <span class={`risk-badge ${riskBadgeClass}`}>{riskLabel}</span>
    </div>

    <p class="category-text">
      Categoría:
      <span>{categoryText}</span>
    </p>

    <div class="summary-content">
      <div class="pie-wrapper">
        <svg class="pie-chart" viewBox="0 0 64 64">
          <circle class="pie-bg" cx="32" cy="32" r={PIE_RADIUS} />
          <circle
            class={`pie-fill ${pieClass}`}
            cx="32"
            cy="32"
            r={PIE_RADIUS}
            stroke-dasharray={mainStrokeDasharray}
          />
          <text
            x="50%"
            y="50%"
            text-anchor="middle"
            dominant-baseline="central"
            class="pie-label"
          >
            {#if vtRiskPercent == null}
              --
            {:else}
              {Math.round(vtRiskPercent)}%
            {/if}
          </text>
        </svg>
        <p class="pie-caption">
          Nivel de riesgo según VirusTotal (0% = ningún motor en contra).
        </p>
      </div>

      <div>
        <p class="status-text">
          <strong>Modelo CybFox:</strong>
          {#if cybfoxScore == null}
            sin datos
          {:else}
            {Math.round(100 - cybfoxScore)} / 100 (riesgo estimado)
          {/if}
        </p>

        <p class="status-text">
          <strong>VirusTotal:</strong>
          {#if vtBadEngines == null || vtTotalEngines == null}
            sin datos agregados
          {:else}
            {vtBadEngines} / {vtTotalEngines} motores lo marcan como malicioso o
            sospechoso
          {/if}
        </p>

        {#if autoError}
          <p class="status-text" style="color:#fca5a5;">
            {autoError}
          </p>
        {:else if cybfoxScore != null}
          <!-- Esquema igual que en blocked.js para CybFox -->
          <p class="status-text">
            {#if cybfoxScore >= 90}
              Score CybFox muy bajo (sitio generalmente confiable).
            {:else if cybfoxScore >= 70}
              Score CybFox medio/bajo (recomendado navegar con precaución).
            {:else if cybfoxScore >= 40}
              Score CybFox alto (indicios de comportamiento riesgoso).
            {:else}
              Score CybFox muy alto (recomendado NO continuar).
            {/if}
          </p>
        {:else if vtTotalEngines && vtTotalEngines > 0}
          <!-- Cuando no hay CybFox, explicamos usando VT -->
          <p class="status-text">
            {#if vtBadEngines === 0}
              Sin detecciones en VirusTotal: ningún motor marca la URL como
              maliciosa o sospechosa.
            {:else if vtBadEngines === 1}
              1 motor de seguridad marca esta URL como sospechosa. Recomendado
              navegar con precaución.
            {:else if vtBadEngines <= 5}
              Varios motores marcan esta URL como maliciosa o sospechosa. Evita
              introducir contraseñas o datos sensibles.
            {:else}
              Muchos motores de seguridad marcan esta URL como maliciosa. Se
              recomienda NO continuar.
            {/if}
          </p>
        {:else}
          <p class="status-text">
            Este indicador se basa en cuántos motores de VirusTotal reportan la
            URL como maliciosa o sospechosa para estimar el nivel de riesgo.
          </p>
        {/if}
      </div>
    </div>
  </section>

  <!-- IPQS (manual) -->
  {#if ipqsSafePercent !== null || ipqsError}
    <section class="summary-card">
      <div class="summary-header">
        <span class="summary-title">IPQualityScore (manual)</span>
        <span class={`risk-badge ${ipqsRiskBadgeClass}`}>{ipqsRiskLabel}</span>
      </div>

      <p class="category-text">
        Score de IPQS calculado solo cuando tú lo solicitas.
      </p>

      <div class="summary-content">
        <div class="pie-wrapper">
          <svg class="pie-chart" viewBox="0 0 64 64">
            <circle class="pie-bg" cx="32" cy="32" r={PIE_RADIUS} />
            <circle
              class={`pie-fill ${ipqsPieClass}`}
              cx="32"
              cy="32"
              r={PIE_RADIUS}
              stroke-dasharray={ipqsStrokeDasharray}
            />
            <text
              x="50%"
              y="50%"
              text-anchor="middle"
              dominant-baseline="central"
              class="pie-label"
            >
              {#if ipqsSafePercent == null}
                --
              {:else}
                {Math.round(ipqsSafePercent)}%
              {/if}
            </text>
          </svg>
          <p class="pie-caption">Seguridad estimada según IPQS</p>
        </div>

        <div>
          <p class="status-text">
            <strong>Riesgo IPQS:</strong>
            {#if ipqsScore == null}
              sin datos
            {:else}
              {Math.round(ipqsScore)} / 100 (0 seguro – 100 muy riesgoso)
            {/if}
          </p>
          {#if ipqsError}
            <p class="status-text" style="color:#fca5a5;">{ipqsError}</p>
          {:else}
            <p class="status-text">
              Este score proviene directamente de IPQualityScore y no se usa en
              el bloqueo automático, solo como referencia adicional.
            </p>
          {/if}
        </div>
      </div>
    </section>
  {/if}

  <!-- CRT -->
  {#if crtStatusText || crtError}
    <section class="summary-card">
      <div class="summary-header">
        <span class="summary-title">Certificado SSL / CRT</span>
        <span class={`risk-badge ${crtRiskBadgeClass}`}>{crtRiskLabel}</span>
      </div>

      <p class="category-text">
        Estado del certificado del sitio (solo cuando ejecutas el escaneo).
      </p>

      <div>
        {#if crtError}
          <p class="status-text" style="color:#fca5a5;">{crtError}</p>
        {:else}
          <p class="status-text">{crtStatusText}</p>
          {#if crtIssuer}
            <p class="status-text">
              <strong>Emisor:</strong>
              {crtIssuer}
            </p>
          {/if}
          {#if crtValidTo}
            <p class="status-text">
              <strong>Validez:</strong>
              {crtValidTo}
            </p>
          {/if}
        {/if}
      </div>
    </section>
  {/if}

  <!-- TAGS -->
  <section class="status-card">
    <div class="status-header">
      <span class="status-title">Tus etiquetas para este sitio</span>
      <span class="status-tag">{domain || "Sitio actual"}</span>
    </div>

    <div class="tags-wrapper">
      {#if tags.length === 0}
        <p class="no-tags">
          Aún no has etiquetado este sitio. Usa las etiquetas para recordarte
          por qué confías o desconfías de él.
        </p>
      {:else}
        <div class="tags-grid">
          {#each tags as tag}
            <span class={`chip ${chipClass(tag)}`}>
              {tag}
              <button
                class="chip-remove"
                on:click={() => removeTag(tag)}
                aria-label="Quitar etiqueta"
              >
                ×
              </button>
            </span>
          {/each}
        </div>
      {/if}

      <div class="custom-tag-row">
        <select bind:value={selectedDefaultTag}>
          <option value="">Añadir etiqueta…</option>
          {#each DEFAULT_TAG_OPTIONS as opt}
            <option value={opt}>{opt}</option>
          {/each}
        </select>
        <button
          class="custom-tag-btn"
          on:click={addSelectedTag}
          disabled={!selectedDefaultTag}
        >
          +
        </button>
      </div>
    </div>
  </section>

  <!-- ACCIONES -->
  <section class="actions">
    <button on:click={runIpqsScan} disabled={loadingIpqs || !currentUrl}>
      {#if loadingIpqs}
        Escaneando con IPQS…
      {:else}
        Escanear con IPQS
      {/if}
    </button>

    <button on:click={runCrtScan} disabled={loadingCrt || !domain}>
      {#if loadingCrt}
        Escaneando certificado…
      {:else}
        Escanear certificado
      {/if}
    </button>
  </section>

  <section class="actions actions-secondary">
    <button on:click={runTestApi}>Test API</button>
    <button on:click={openDashboard}>Abrir dashboard de la página</button>
  </section>

  {#if testMessage}
    <p class="status-text" style="margin-top:0.25rem;">
      {testMessage}
    </p>
  {/if}
</div>
