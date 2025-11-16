<script>
  import { onMount } from 'svelte';
  import { fade, fly, scale } from 'svelte/transition';

  let currentUrl = '';
  let loading = false;
  let status = '';
  let resultText = '';
  let lastAction = '';

  async function loadCurrentTabUrl() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      currentUrl = tab?.url ?? '';
    } catch (err) {
      currentUrl = 'No se pudo obtener la URL';
    }
  }

  async function callBackend(endpoint) {
    try {
      loading = true;
      status = 'Escaneando...';
      resultText = '';

      const res = await fetch(`http://localhost:3000${endpoint}`);
      const data = await res.json();
      resultText = JSON.stringify(data, null, 2);
      status = 'Escaneo completado';
    } catch (err) {
      status = 'Error al comunicar con el backend';
      resultText = String(err);
    } finally {
      loading = false;
    }
  }

  function handlePrintUrl() {
    lastAction = 'URL actual';
    status = 'URL detectada';
    resultText = currentUrl || 'No se encontró URL activa';
  }

  async function handleTestApi() {
    lastAction = 'Test API';
    await callBackend('/api/test');
  }

  async function handleInvertUrl() {
    lastAction = 'Invertir URL';
    if (!currentUrl) {
      status = 'No hay URL para invertir';
      return;
    }
    await callBackend(`/api/invert-url?url=${encodeURIComponent(currentUrl)}`);
  }

  async function handleIpqs() {
    lastAction = 'IPQS check';
    if (!currentUrl) {
      status = 'No hay URL para analizar';
      return;
    }
    await callBackend(`/api/check-ipqs?url=${encodeURIComponent(currentUrl)}`);
  }

  function openDashboard() {
    chrome.tabs.create({
      url: chrome.runtime.getURL('frontend/dist/index.html?view=dashboard')
    });
  }

  onMount(() => {
    // Solo obtener URL al abrir el popup
    loadCurrentTabUrl();
  });
</script>

<main
  class="popup"
  class:loading={loading}
  in:fade={{ duration: 200 }}
>
  <header class="header" in:fly={{ y: -10, duration: 250 }}>
    <div class="logo-dot"></div>
    <div class="title-block">
      <h1>CybFox Security Scanner</h1>
      <p class="subtitle">Analiza la seguridad de la página actual</p>
    </div>
  </header>

  <section class="url-card" in:fly={{ y: -5, duration: 260, delay: 100 }}>
    <div class="label">URL actual</div>
    <div class="url-text" title={currentUrl}>{currentUrl || 'Cargando URL...'}</div>
    <button class="secondary" on:click={loadCurrentTabUrl}>Refrescar URL</button>
  </section>

  <section class="scanner-section" in:scale={{ duration: 250, start: 0.92 }}>
    <div class="scanner-frame">
      <div class="scanner-grid"></div>
      <div class="scanner-line" aria-hidden={!loading}></div>
      <div class="scanner-center">
        {#if loading}
          <span>Escaneando…</span>
        {:else}
          <span>Listo para escanear</span>
        {/if}
      </div>
    </div>
  </section>

  <section class="actions" in:fly={{ y: 8, duration: 260, delay: 80 }}>
    <button on:click={handlePrintUrl}>Mostrar URL</button>
    <button on:click={handleTestApi}>Test API</button>
    <button on:click={handleInvertUrl}>Invertir URL</button>
    <button on:click={handleIpqs}>IPQS check</button>
  </section>

  <!-- 🔵 Botón para ir al dashboard -->
  <button
    class="dashboard-button"
    on:click={openDashboard}
    in:fade={{ duration: 220, delay: 100 }}
  >
    Ver historial de análisis
  </button>

  <section class="status-card" in:fade={{ duration: 220, delay: 120 }}>
    <div class="status-header">
      <span class="status-title">Estado</span>
      {#if lastAction}
        <span class="status-tag">{lastAction}</span>
      {/if}
    </div>

    <p class="status-text">{status || 'Sin acciones aún.'}</p>

    {#if resultText}
      <pre class="result-box">{resultText}</pre>
    {/if}
  </section>
</main>
