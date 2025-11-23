<script>
  import ChatWindow from "./ChatWindow.svelte";  
  export let open = false;
  export let close;

  let message = "";
  let chat = [];      // para mostrar mensajes en pantalla
  let history = [];   // historial real que se manda a Gemini
  let loading = false;

  async function sendMessage() {
    
    if (!message.trim()) return;
    loading = true;

    const userMsg = message;

    // muestra inmediato el mensaje del usuario
    chat = [...chat, { role: "user", text: userMsg }];
    message = "";

    try {
      const res = await fetch("http://localhost:3000/assistant/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: userMsg,
          history
        })
      });

      const data = await res.json();

      if (data.success) {
        // actualiza historial interno
        history = data.history;

        // agrega respuesta del modelo al chat visual
        chat = [...chat, { role: "model", text: data.reply }];
      } else {
        chat = [...chat, { role: "model", text: "No pude responder 🫠" }];
      }
    } catch (err) {
      console.error(err);
      chat = [...chat, { role: "model", text: "Error conectando con el server 😵" }];
    }

    loading = false;
  }

  function closeChat() {
    close();
  }
</script>

<ChatWindow
  open={open}
  chat={chat}
  bind:message={message}
  loading={loading}
  sendMessage={sendMessage}
  close={closeChat}
/>



