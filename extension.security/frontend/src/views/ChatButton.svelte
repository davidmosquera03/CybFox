<script>
  export let toggle;
</script>

<button class="fab" on:click={toggle}>
  💬
</button>

<style>
  .fab {
    position: fixed;
    bottom: 20px;
    right: 20px;

    width: 60px;
    height: 60px;
    background: rgba(15, 23, 42, 0.9);
    color: white;
    border: 2px solid #f97316;
    border-radius: 50%;
    display: flex;
    justify-content: center;
    align-items: center;
    font-size: 1.8rem;
    cursor: pointer;
    box-shadow: 0 0 25px rgba(249, 115, 22, 0.5);
    transition: 0.2s ease;

    /* flotante por encima del dashboard */
    z-index: 2147483647;
  }

  .fab:hover {
    transform: scale(1.1);
    background: rgba(249, 115, 22, 0.28);
  }
</style>
