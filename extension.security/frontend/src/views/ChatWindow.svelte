<script>
  export let open = false;
  export let chat = [];
  export let message = "";
  export let loading = false;
  export let sendMessage;
  export let close;
</script>

<style>

  .window {
    position: fixed;
    bottom: 90px;
    right: 20px;
    width: 330px;
    height: 430px;
    background: #181818;
    color: white;
    border-radius: 12px;
    box-shadow: 0 0 20px rgba(0,0,0,0.4);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    z-index: 999999999 !important;
    pointer-events: auto;
  }

  .header {
    background: #242424;
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-weight: bold;
  }

  .messages {
    flex: 1;
    overflow-y: auto;
    padding: 10px;
  }

  .input-area {
    padding: 10px;
    border-top: 1px solid #333;
    display: flex;
    gap: 8px;
    background: #181818;
  }

  input {
    flex: 1;
    padding: 8px;
    background: #2a2a2a;
    border: none;
    outline: none;
    border-radius: 6px;
    color: white;
  }

  button {
    padding: 8px 12px;
    background: #005bea;
    border: none;
    border-radius: 6px;
    color: white;
    cursor: pointer;
    font-weight: bold;
  }

  .msg-user {
    text-align: right;
    color: #0af;
    margin-bottom: 6px;
  }

  .msg-ai {
    text-align: left;
    color: #0f0;
    margin-bottom: 6px;
  }
</style>

{#if open}
<div class="window">
  <div class="header">
    CybFox
    <button class="close-btn" on:click={close}>×</button>

  </div>

  <div class="messages">
    {#each chat as m}
      <div class={m.role === "user" ? "msg-user" : "msg-ai"}>
        {m.text}
      </div>
    {/each}

    {#if loading}
      <div class="msg-ai">Escribiendo...</div>
    {/if}
  </div>

  <div class="input-area">
    <input
      type="text"
      bind:value={message}
      placeholder="Escribe algo..."
      on:keydown={(e) => e.key === "Enter" && sendMessage()}

    />
    <button on:click={sendMessage}>Enviar</button>
  </div>
</div>
{/if}
