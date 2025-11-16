<script>
  import '../app.css';

  let pages = [];
  let loading = false;
  let error = '';

  // Aquí luego llamas a tu backend para traer historial:
  // onMount(async () => {
  //   loading = true;
  //   try {
  //     const res = await fetch('http://localhost:3000/api/db/get-all-pages');
  //     pages = await res.json();
  //   } catch (e) {
  //     error = 'No se pudo cargar el historial';
  //   } finally {
  //     loading = false;
  //   }
  // });
</script>

<main class="dashboard">
  <header class="dashboard-header">
    <h1>CybFox – Historial de análisis</h1>
    <p>Resumen de las URLs analizadas por la extensión.</p>
  </header>

  {#if loading}
    <p>Cargando historial…</p>
  {:else if error}
    <p>{error}</p>
  {:else if pages.length === 0}
    <p>No hay análisis registrados todavía.</p>
  {:else}
    <table class="history-table">
      <thead>
        <tr>
          <th>Fecha</th>
          <th>URL</th>
          <th>Riesgo</th>
          <th>Fuente</th>
        </tr>
      </thead>
      <tbody>
        {#each pages as page}
          <tr>
            <td>{page.date}</td>
            <td title={page.url}>{page.url}</td>
            <td>{page.risk}</td>
            <td>{page.source}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</main>
