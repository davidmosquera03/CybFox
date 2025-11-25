<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { fly } from "svelte/transition";

  // 👀 Recibes el tema desde el dashboard
  export let theme: "dark" | "light" = "dark";

  // Fotos reales
  import deivid from "../assets/david.png";
  import mari from "../assets/mari.png";
  import lu from "../assets/luisa.png";

  // Iconos GitHub / LinkedIn
  import githubIconB from "../assets/github-mark-white.svg";
  import githubIconN from "../assets/github-mark.svg";
  import linkedinAzul from "../assets/linkedin-azul.svg";
  import linkedinBlanco from "../assets/linkedin-negro.svg";

  const members = [
    {
      name: "David Hernandez Mosquera",
      avatar: deivid,
      linkedin:
        "https://www.linkedin.com/in/david-hernandez-mosquera-b9198a273/",
      github: "https://github.com/davidmosquera03"
    },
    {
      name: "María Isabel Solá Valle",
      avatar: mari,
      linkedin: "https://www.linkedin.com/in/misv-1n93n13r14/",
      github: "https://github.com/mystic23"
    },
    {
      name: "Luisa Fernanda Guzmán Santoya",
      avatar: lu,
      linkedin: "https://www.linkedin.com/in/luisa-guzman-21800a2b5/",
      github: "https://github.com/Ahiruk"
    }
  ];

  const ROTATE_MS = 7000;

  let currentIndex = 0;
  let intervalId: number | null = null;

  // 🔁 rotación automática
  function next() {
    currentIndex = (currentIndex + 1) % members.length;
  }

  function prev() {
    currentIndex = (currentIndex - 1 + members.length) % members.length;
  }

  onMount(() => {
    intervalId = window.setInterval(next, ROTATE_MS);
  });

  onDestroy(() => {
    if (intervalId !== null) window.clearInterval(intervalId);
  });

  function pauseRotation() {
    if (intervalId !== null) {
      window.clearInterval(intervalId);
      intervalId = null;
    }
  }

  function resumeRotation() {
    if (intervalId === null) {
      intervalId = window.setInterval(next, ROTATE_MS);
    }
  }

  // 🎨 Iconos según modo
  $: isLightMode = theme === "light";
  $: githubIcon = isLightMode ? githubIconN : githubIconB;
  $: linkedinIcon = isLightMode ? linkedinAzul : linkedinBlanco;
</script>

<section
  class="team-wrapper"
  role="group"
  aria-label="Carrusel del equipo CybFox"
  on:mouseenter={pauseRotation}
  on:mouseleave={resumeRotation}
>
  <div class="team-header">
    <span class="pill">Equipo CybFox</span>
  </div>

  <div class="team-card-slot">
    {#each members as member, i}
      {#if i === currentIndex}
        <article
          class="team-card"
          in:fly={{ x: 40, duration: 260 }}
          out:fly={{ x: -40, duration: 220 }}
        >
          <!-- FOTO RECTANGULAR -->
          <div class="avatar-rect">
            <img src={member.avatar} alt={`Foto de ${member.name}`} />
          </div>

          <div class="member-info">
            <h3>{member.name}</h3>
          </div>

          <div class="links-row">
            <a
              href={member.linkedin}
              target="_blank"
              rel="noreferrer"
              class="link-btn"
            >
              <img src={linkedinIcon} alt="LinkedIn" />
              <span>LinkedIn</span>
            </a>
            <a
              href={member.github}
              target="_blank"
              rel="noreferrer"
              class="link-btn"
            >
              <img src={githubIcon} alt="GitHub" />
              <span>GitHub</span>
            </a>
          </div>

          <div class="dots">
            {#each members as _, idx}
              <button
                class:active={idx === currentIndex}
                on:click={() => (currentIndex = idx)}
                aria-label={`Ver integrante ${idx + 1}`}
              ></button>
            {/each}
          </div>
        </article>
      {/if}
    {/each}
  </div>

  <!-- FLECHAS LATERALES CENTRADAS -->
  <div class="arrows" aria-hidden="false">
    <button on:click={prev} aria-label="Integrante anterior">
      ‹
    </button>
    <button on:click={next} aria-label="Siguiente integrante">
      ›
    </button>
  </div>
</section>

<style>
  .team-wrapper {
    margin-top: 14px;
    padding: 16px 16px 18px;
    border-radius: 22px;
    position: relative;
    overflow: hidden;

    background: radial-gradient(
      circle at 0% 0%,
      rgba(59, 130, 246, 0.35),
      rgba(15, 23, 42, 0.96)
    );
    border: 1px solid rgba(148, 163, 184, 0.6);
    box-shadow:
      0 0 18px rgba(59, 130, 246, 0.6),
      0 12px 30px rgba(15, 23, 42, 0.9);
  }

  .team-header {
    display: flex;
    justify-content: flex-start;
    margin-bottom: 10px;
  }

  .pill {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    padding: 4px 14px;
    border-radius: 999px;
    border: 1px solid rgba(191, 219, 254, 0.9);
    background: rgba(15, 23, 42, 0.85);
    color: #bfdbfe;
  }

  .team-card-slot {
    position: relative;
    height: 320px; /* card más larga */
    overflow: hidden;
  }

  .team-card {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 4px 8px 10px;
  }

  /* FOTO RECTANGULAR */
.avatar-rect {
  width: 160px;      /* Aumenta si quieres más grande */
  height: 210px;     /* Mantén una proporción vertical bonita */
  border-radius: 18px;

  overflow: hidden;
  margin: 0 auto;

  display: flex;
  align-items: center;
  justify-content: center;

  background: radial-gradient(circle at 30% 0%, #0f172a, #020617);
  border: 2px solid #38bdf8;

  box-shadow:
    0 0 12px rgba(56, 189, 248, 0.9),
    0 0 24px rgba(56, 189, 248, 0.5);
}

  .avatar-rect img {
    width: 100%;
    height: 100%;
    object-fit: cover;   /* ESTO corrige todas las fotos */
    object-position: center;
  }

  .member-info {
    text-align: center;
  }

  .member-info h3 {
    margin: 6px 0 0;
    font-size: 0.95rem;
    font-weight: 600;
  }

  .links-row {
    display: flex;
    justify-content: center;
    gap: 10px;
    margin-top: 10px;
  }

  .link-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 0.78rem;
    padding: 5px 10px;
    border-radius: 999px;
    text-decoration: none;
    border: 1px solid rgba(148, 163, 184, 0.85);
    color: #e5e7eb;
    background: rgba(15, 23, 42, 0.95);
    transition:
      background 0.16s ease,
      box-shadow 0.16s ease,
      transform 0.1s ease;
  }

  .link-btn img {
    width: 14px;
    height: 14px;
    display: block;
  }

  .link-btn:hover {
    background: radial-gradient(
      circle at 0% 0%,
      rgba(56, 189, 248, 0.7),
      rgba(15, 23, 42, 1)
    );
    box-shadow: 0 0 14px rgba(56, 189, 248, 0.9);
    transform: translateY(-1px);
  }

  .dots {
    display: flex;
    justify-content: center;
    gap: 6px;
    margin-top: 12px;
  }

  .dots button {
    width: 7px;
    height: 7px;
    border-radius: 999px;
    border: none;
    background: rgba(148, 163, 184, 0.5);
    padding: 0;
    cursor: pointer;
    transition:
      background 0.18s ease,
      transform 0.12s ease,
      box-shadow 0.16s ease;
  }

  .dots button.active {
    background: #38bdf8;
    transform: scale(1.3);
    box-shadow: 0 0 10px rgba(56, 189, 248, 0.9);
  }

  /* FLECHAS LATERALES NEÓN */
  .arrows {
    position: absolute;
    top: 50%;
    left: 0;
    right: 0;
    transform: translateY(-50%);
    display: flex;
    justify-content: space-between;
    padding: 0 8px;
    pointer-events: none;
  }

  .arrows button {
    pointer-events: auto;
    border: none;
    border-radius: 999px;
    width: 28px;
    height: 28px;
    font-size: 1rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: center;
    background: radial-gradient(circle at 30% 0%, #0b1120, #020617);
    color: #e5e7eb;
    box-shadow:
      0 0 10px rgba(15, 23, 42, 0.9),
      0 0 14px rgba(56, 189, 248, 0.7);
    cursor: pointer;
    transition:
      background 0.18s ease,
      transform 0.1s ease,
      box-shadow 0.16s ease;
  }

  .arrows button:hover {
    background: radial-gradient(circle at 30% 0%, #38bdf8, #0f172a);
    color: #020617;
    transform: translateY(-1px);
    box-shadow:
      0 0 18px rgba(56, 189, 248, 0.9),
      0 0 25px rgba(56, 189, 248, 0.7);
  }

  /* MODO CLARO */
  :global(html[data-theme="light"]) .team-wrapper {
    background: radial-gradient(circle at 0% 0%, #e0f2fe, #ffffff);
    border-color: #d1d5db;
    box-shadow: 0 10px 25px rgba(15, 23, 42, 0.12);
  }

  :global(html[data-theme="light"]) .pill {
    background: #eff6ff;
    color: #1d4ed8;
    border-color: #bfdbfe;
  }

  :global(html[data-theme="light"]) .link-btn {
    background: #f9fafb;
    color: #0f172a;
    border-color: #cbd5e1;
  }

  :global(html[data-theme="light"]) .link-btn:hover {
    background: #dbeafe;
    box-shadow: 0 0 12px rgba(59, 130, 246, 0.5);
  }

  :global(html[data-theme="light"]) .arrows button {
    background: #e5f0ff;
    color: #1e293b;
    box-shadow: 0 0 10px rgba(148, 163, 184, 0.6);
  }

  :global(html[data-theme="light"]) .arrows button:hover {
    background: #bfdbfe;
    box-shadow: 0 0 16px rgba(59, 130, 246, 0.7);
  }
</style>
