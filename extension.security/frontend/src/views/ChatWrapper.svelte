<script>
  import ChatWindow from "./ChatWindow.svelte";  
  export let open = false;
  export let close;

  let message = "";
  let chat = [];
  let loading = false;

  async function sendMessage() {
    if (!message.trim()) return;
    loading = true;

    try {
      const res = await fetch("http://localhost:3000/assistant/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message,
          history: chat
        })
      });

      const data = await res.json();
      if (data.success) chat = data.history;
    } catch (err) {
      console.error(err);
    }

    message = "";
    loading = false;
  }

  function closeChat() {
    close(); // avisa al padre
  }
</script>

<ChatWindow
  open={open}
  chat={chat}
  message={message}
  loading={loading}
  sendMessage={sendMessage}
  close={closeChat}
/>
