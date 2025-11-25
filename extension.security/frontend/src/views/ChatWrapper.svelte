<script>
  import ChatWindow from "./ChatWindow.svelte";

  export let open = false;
  export let close;
  export let dashboard = null;

  let mode = "";
  let message = "";
  let chat = [];
  let history = []; // historial REAL que se envía al backend
  let loading = false;

  // Mensaje inicial por modo
  function welcomeMessageFor(mode) {
    const map = {
      simple:
        "🟢 Estás en Modo Sencillo. Te explicaré todo de manera clara, humana y sin tecnicismos.",
      technical:
        "🔵 Estás en Modo Técnico. Puedo darte un análisis detallado basado en los datos reales del dashboard.",
      educational:
        "🟣 Estás en Modo Educativo. Te enseñaré con ejemplos reales qué hace peligrosa o segura una página.",
      professor:
        "🟡 Estás en Modo Profesor. Recibirás mini-clases cortas con ejercicios y preguntas."
    };
    return map[mode] || "";
  }

  // Sugerencias por modo
  function capabilityHintFor(mode) {
    switch (mode) {
      case "simple":
        return `
Puedes pedirme cosas como:
- Explícame qué tan riesgosa es esta página.
- Dime en pocas palabras si es confiable.
- ¿Qué me recomiendas hacer con este sitio?`;
      case "technical":
        return `
Puedes pedirme:
- Dame un informe técnico completo.
- Analiza el certificado SSL del dominio.
- Interpreta flags IPQS y VirusTotal.
- Muéstrame el resumen técnico del dashboard.`;
      case "educational":
        return `
Puedes pedirme:
- Explícame paso a paso esta página.
- Dame ejemplos de phishing.
- Enséñame qué revisar antes de poner mi tarjeta.`;
      case "professor":
        return `
Puedes pedirme:
- Lista de clases.
- Dame la clase 1, 2, 3, 4 o 5.
- Dame una clase al azar.
- Hazme una pregunta para practicar.`;
      default:
        return "";
    }
  }

  // Cuando elige modo
  function chooseMode(m) {
    mode = m;
    chat = [];
    history = []; // limpiar historial real

    // Bienvenida inicial
    chat = [
      { role: "assistant", text: welcomeMessageFor(m) },
      { role: "assistant", text: capabilityHintFor(m) }
    ];
  }

  // Regresar a selección de modo
  function goBack() {
    mode = "";
    message = "";
    chat = [];
    history = [];
  }

  // ENVÍO REAL AL BACKEND
  async function sendMessage() {
    if (!message.trim() || !mode) return;
    loading = true;

    const userText = message;
    message = "";

    // Mostrar mensaje del usuario
    chat = [...chat, { role: "user", text: userText }];

    // Agregar al historial REAL
    history = [...history, { role: "user", text: userText }];

    try {
      const res = await fetch("http://localhost:3000/assistant/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: userText,
          history,       // historial REAL
          mode,
          dashboard: dashboard || {}
        })
      });

      const data = await res.json();

      if (data.success) {
        // Backend devuelve historial completo
        history = data.history;

        // Última respuesta del modelo
        chat = [...chat, { role: "assistant", text: data.reply }];
      } else {
        chat = [
          ...chat,
          { role: "assistant", text: "No pude responder correctamente." }
        ];
      }
    } catch (err) {
      console.error("Error:", err);
      chat = [
        ...chat,
        {
          role: "assistant",
          text: "Hubo un problema al conectar con el servidor CybFox."
        }
      ];
    } finally {
      loading = false;
    }
  }

  function closeChat() {
    close();
    mode = "";
    chat = [];
    history = [];
    message = "";
  }
</script>

{#if open && mode === ""}
  <div class="welcome">
    <h1 class="welcome-title">🦊 Bienvenido a <span>CybFox AI</span></h1>
    <p class="welcome-subtitle">
      Tu asistente inteligente para analizar páginas web y detectar riesgos reales.
    </p>
    <p class="welcome-choose">¿Cómo quieres que te explique esta página?</p>

    <button class="mode-btn" on:click={() => chooseMode("simple")}>
      🟢 Modo Sencillo
      <span class="desc">Explicaciones rápidas y humanas.</span>
    </button>

    <button class="mode-btn" on:click={() => chooseMode("technical")}>
      🔵 Modo Técnico
      <span class="desc">Análisis profesional basado en datos.</span>
    </button>

    <button class="mode-btn" on:click={() => chooseMode("educational")}>
      🟣 Modo Educativo
      <span class="desc">Aprende ciberseguridad con ejemplos reales.</span>
    </button>

    <button class="mode-btn" on:click={() => chooseMode("professor")}>
      🟡 Modo Profesor
      <span class="desc">Mini-clases y ejercicios guiados.</span>
    </button>
  </div>
{/if}

{#if open && mode !== ""}
  <ChatWindow
    {open}
    {chat}
    bind:message
    {loading}
    {sendMessage}
    close={closeChat}
    {mode}
    back={goBack}
  />
{/if}
<style>
  .welcome {
    position: fixed;
    bottom: 90px;
    right: 20px;
    width: 330px;
    height: 430px;
    background: rgba(15, 23, 42, 0.96);
    border: 2px solid #f97316;
    border-radius: 15px;
    padding: 24px;
    box-shadow: 0 0 25px rgba(249, 115, 22, 0.35);
    animation: fadeIn 0.35s ease-out;
    /* FIX DEFINITIVO */
    overflow: visible !important;
    /* y mantener por encima del dashboard */
    z-index: 2147483646;
  }

  @keyframes fadeIn {
    from {
      opacity: 0;
      transform: translateY(6px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .welcome-title {
    font-size: 22px;
    font-weight: 700;
    color: #f97316;
    text-align: center;
  }

  .welcome-title span {
    color: #e5e7eb;
  }

  .welcome-subtitle {
    color: #94a3b8;
    margin-top: 6px;
    margin-bottom: 14px;
    text-align: center;
    font-size: 13px;
  }

  .welcome-choose {
    text-align: center;
    font-size: 15px;
    margin-bottom: 14px;
    color: #f1f5f9;
  }

  .mode-btn {
    width: 100%;
    background: rgba(15, 23, 42, 0.85);
    border: 2px solid #f97316;
    padding: 10px 12px;
    margin-bottom: 12px;
    border-radius: 10px;
    color: #f97316;
    font-size: 15px;
    font-weight: bold;
    cursor: pointer;
    transition: 0.2s;
    text-align: left;
  }

  .mode-btn:hover {
    background: rgba(249, 115, 22, 0.15);
    box-shadow: 0 0 18px rgba(249, 115, 22, 0.45);
  }

  .desc {
    display: block;
    color: #cbd5e1;
    font-weight: normal;
    font-size: 13px;
    margin-top: 3px;
  }
</style>
