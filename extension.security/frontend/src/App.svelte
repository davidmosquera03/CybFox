<script>
  import './app.css';
  import PopupView from './views/PopupView.svelte';
  import DashboardView from './views/DashboardView.svelte';

  const params = new URLSearchParams(window.location.search);
  const view = params.get('view') ?? 'popup'; // 'popup' o 'dashboard'
</script>

{#if view === 'dashboard'}
  <DashboardView />
{:else}
  <PopupView />
{/if}

