<script>
  export let toggle;
</script>

<style>
  .fab {
    position: fixed;
    bottom: 20px;
    right: 20px;
    width: 60px;
    height: 60px;
    background: #005bea;
    color: white;
    border-radius: 50%;
    display: flex;
    justify-content: center;
    align-items: center;
    font-size: 1.8rem;
    cursor: pointer;
    box-shadow: 0 0 12px rgba(0,0,0,0.3);
    transition: transform .1s;
  }

  .fab:hover {
    transform: scale(1.07);
  }
</style>

<button class="fab" on:click={toggle}>
  💬
</button>
