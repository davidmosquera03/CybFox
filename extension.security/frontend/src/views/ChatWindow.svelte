<script>
  import { marked } from "marked";
  export let open = false;
  export let chat = [];
  export let message = "";
  export let loading = false;
  export let sendMessage;
  export let close;
  export let mode = "simple";
  export let back;

  const MODE_INFO = {
    simple: {
      label: "Modo sencillo",
      dot: "🟢",
    },
    technical: {
      label: "Modo técnico",
      dot: "🔵",
    },
    educational: {
      label: "Modo educativo",
      dot: "🟣",
    },
    professor: {
      label: "Modo profesor",
      dot: "🟡",
    },
  };

  $: modeInfo = MODE_INFO[mode] ?? MODE_INFO.simple;

  function handleKey(event) {
    // Enter = enviar, Shift+Enter = salto de línea
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      if (!loading && message.trim()) {
        sendMessage();
      }
    }
  }
</script>

{#if open}
  <div class="chat-window">
    <header class="chat-header">
      <button class="icon-btn" on:click={back} aria-label="Cambiar de modo">
        ⬅
      </button>

      <div class="title-block">
        <div class="title-row">
          <span class="app-name">CybFox AI</span>
          <span class="mode-pill">
            {modeInfo.dot} {modeInfo.label}
          </span>
        </div>
        <p class="subtitle">
          Asistente de seguridad para la página que estás analizando.
        </p>
      </div>

      <button class="icon-btn close" on:click={close} aria-label="Cerrar chat">
        ✕
      </button>
    </header>

    <main class="chat-body">
      {#each chat as msg}
        <div class={msg.role === "user" ? "bubble user" : "bubble ai"}>
          <div class="bubble-inner">
            {@html marked.parse(msg.text || "")}
          </div>
        </div>
      {/each}

      {#if loading}
        <div class="bubble ai typing">
          <div class="typing-dots">
            <span></span><span></span><span></span>
          </div>
          <span class="typing-text">CybFox está pensando…</span>
        </div>
      {/if}
    </main>

    <footer class="chat-footer">
      <textarea
        class="chat-input"
        rows="2"
        bind:value={message}
        placeholder="Escribe tu mensaje. (Enter para enviar)"
        on:keydown={handleKey}
      ></textarea>

      <button
        class="send-btn"
        on:click={sendMessage}
        disabled={loading || !message.trim()}
      >
        {#if loading}
          Enviando…
        {:else}
          Enviar
        {/if}
      </button>
    </footer>
  </div>
{/if}

<style>
  .chat-window {
    position: fixed;
    bottom: 90px;
    right: 20px;
    width: 340px;
    max-height: 520px;
    display: flex;
    flex-direction: column;
    background: radial-gradient(circle at top, #020617, #020617 45%, #000);
    border-radius: 18px;
    border: 2px solid #f97316;
    box-shadow: 0 0 28px rgba(249, 115, 22, 0.5);
    overflow: hidden;
    z-index: 2147483647;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text",
      "Segoe UI", sans-serif;
    color: #e5e7eb;
  }

  .chat-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 12px;
    border-bottom: 1px solid rgba(148, 163, 184, 0.3);
    background: radial-gradient(circle at 0 0, #1f2937, #020617);
  }

  .title-block {
    flex: 1;
    min-width: 0;
  }

  .title-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .app-name {
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-size: 0.78rem;
  }

  .mode-pill {
    font-size: 0.72rem;
    border-radius: 999px;
    padding: 2px 8px;
    background: rgba(15, 23, 42, 0.9);
    border: 1px solid rgba(249, 115, 22, 0.9);
    color: #fed7aa;
    white-space: nowrap;
  }

  .subtitle {
    margin: 2px 0 0;
    font-size: 0.76rem;
    color: #9ca3af;
  }

  .icon-btn {
    border: none;
    background: transparent;
    color: #e5e7eb;
    font-size: 0.9rem;
    cursor: pointer;
    padding: 4px;
    border-radius: 999px;
    transition: background 0.15s ease, transform 0.1s ease;
  }

  .icon-btn:hover {
    background: rgba(15, 23, 42, 0.8);
    transform: translateY(-1px);
  }

  .icon-btn.close:hover {
    background: rgba(185, 28, 28, 0.8);
  }

  .chat-body {
    flex: 1;
    padding: 10px 10px 8px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 6px;
    scrollbar-width: thin;
    scrollbar-color: #6b7280 transparent;
  }

  .chat-body::-webkit-scrollbar {
    width: 6px;
  }

  .chat-body::-webkit-scrollbar-thumb {
    background: #6b7280;
    border-radius: 999px;
  }

  .bubble {
    max-width: 90%;
    display: flex;
  }

  .bubble-inner {
    padding: 7px 10px;
    border-radius: 12px;
    font-size: 0.8rem;
    line-height: 1.25;
    word-wrap: break-word;
    white-space: pre-wrap;
  }

  .bubble.user {
    justify-content: flex-end;
  }

  .bubble.user .bubble-inner {
    background: linear-gradient(135deg, #f97316, #fb923c);
    color: #0b1120;
    border-bottom-right-radius: 2px;
  }

  .bubble.ai {
    justify-content: flex-start;
  }

  .bubble.ai .bubble-inner {
    background: rgba(15, 23, 42, 0.95);
    border: 1px solid rgba(148, 163, 184, 0.7);
    border-bottom-left-radius: 2px;
  }

  .typing {
    align-items: center;
    gap: 6px;
  }

  .typing-dots {
    display: inline-flex;
    gap: 3px;
    margin-right: 4px;
  }

  .typing-dots span {
    width: 5px;
    height: 5px;
    border-radius: 999px;
    background: #f97316;
    animation: bounce 1s infinite ease-in-out;
  }

  .typing-dots span:nth-child(2) {
    animation-delay: 0.15s;
  }
  .typing-dots span:nth-child(3) {
    animation-delay: 0.3s;
  }

  .typing-text {
    font-size: 0.76rem;
    color: #9ca3af;
  }

  .chat-footer {
    border-top: 1px solid rgba(148, 163, 184, 0.3);
    padding: 8px;
    display: flex;
    gap: 6px;
    background: rgba(15, 23, 42, 0.98);
  }

  .chat-input {
    flex: 1;
    resize: none;
    border-radius: 10px;
    border: 1px solid rgba(51, 65, 85, 0.9);
    background: #020617;
    color: #e5e7eb;
    padding: 6px 8px;
    font-size: 0.78rem;
    outline: none;
  }

  .chat-input::placeholder {
    color: #6b7280;
  }

  .chat-input:focus {
    border-color: #f97316;
    box-shadow: 0 0 0 1px rgba(249, 115, 22, 0.6);
  }

  .send-btn {
    border-radius: 999px;
    border: none;
    padding: 6px 14px;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    background: linear-gradient(135deg, #f97316, #ea580c);
    color: #0b1120;
    box-shadow: 0 8px 20px rgba(249, 115, 22, 0.6);
    white-space: nowrap;
  }

  .send-btn:disabled {
    opacity: 0.6;
    cursor: default;
    box-shadow: none;
  }

  @keyframes bounce {
    0%, 80%, 100% {
      transform: scale(0.8);
      opacity: 0.5;
    }
    40% {
      transform: scale(1.1);
      opacity: 1;
    }
  }


  /* NORMALIZACIÓN DE MARKDOWN PARA BURBUJAS */
.bubble-inner p {
  margin: 0;               /* Quita el margen superior/inferior */
}

.bubble-inner ul,
.bubble-inner ol {
  margin: 4px 0;           /* Reduce el espacio entre listas */
  padding-left: 18px;      /* Ajusta sangría */
}

.bubble-inner li {
  margin: 2px 0;           /* Evita viñetas muy espaciadas */
}

.bubble-inner > *:first-child {
  margin-top: 0;
}

.bubble-inner > *:last-child {
  margin-bottom: 0;
}

</style>
