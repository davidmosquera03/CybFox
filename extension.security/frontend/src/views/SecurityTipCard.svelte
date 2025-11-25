<script lang="ts">
  const tips = [
  "Si una página te da mala espina en los primeros dos segundos, créeme: no va a mejorar. El instinto digital también cuenta.",
  "Cuando un sitio te presiona con urgencia, recuerda: la prisa es el mejor cómplice del phishing.",
  "No des clic en un enlace al que no le darías tu número de teléfono. La confianza se gana, incluso online.",
  "Los hackers no descansan; tú sí. Y mientras duermes, CybFox sigue cuidando lo que visitas.",
  "El mejor antivirus siempre será tu sentido común. Ningún software puede reemplazar eso.",
  "Si te ofrecen ‘premios milagrosos’, prepárate para perder algo real. Nada gratis es realmente gratis.",
  "HTTPS implica cifrado, no confianza. También existen sitios maliciosos con candadito.",
  "Los sitios falsos siempre van de afán. Un diseño apresurado dice más que mil certificaciones.",
  "Deja que CybFox revise antes de confiar en una página. Para eso está el panel completo.",
  "Internet es como un barrio desconocido: evita los callejones oscuros y las casas sin número.",
  "Si un sitio te pide claves, corre como si te estuvieran pidiendo la tarjeta física.",
  "Correos dudosos casi siempre son trampas obvias disfrazadas de urgencias falsas.",
  "El phishing evoluciona cada año; tu desconfianza también debería hacerlo.",
  "Si el mensaje parece escrito por alguien con prisa o desesperación, probablemente lo está… por robarte.",
  "Los ladrones digitales aman al usuario que hace clic sin pensar. No seas ese clic fácil.",
  "Ningún pop-up extraño trae buenas noticias. Casi siempre trae problemas.",
  "Si te ofrecen regalos, descuentos imposibles o sorpresas mágicas, el truco está detrás del clic.",
  "Navegar seguro empieza con una desconfianza sana. No es paranoia, es prevención.",
  "Cuando dudes, pregúntale primero a CybFox antes de adelantar clics innecesarios.",
  "Si el sitio parece demasiado bonito para ser real, spoiler: no es real.",
  "Tu contraseña no puede ser ‘123456’ ni variaciones primitivas. Te lo digo con cariño.",
  "No guardes contraseñas en notas del celular. Es como guardar dinero bajo la alfombra.",
  "Los hackers aman cuando tu ortografía falla en un dominio. Ahí es donde te engañan.",
  "Las URL larguísimas ocultan trampas que no deberías descubrir en tu navegador.",
  "Nunca instales nada desde un link que no pediste. Las sorpresas no son seguras.",
  "Los correos urgentes solo son urgentes para quien quiere que hagas clic rápido.",
  "Actualizar el navegador o tus apps evita desastres silenciosos sin que lo notes.",
  "Usar la misma contraseña en todo es como usar la misma llave para tu casa, tu carro y tu diario.",
  "Si la página vibra raro, se mueve raro o te pide cosas raras… investiga antes de continuar.",
  "Los links cortos pueden esconder sustos largos. Verifica el destino antes de entrar.",
  "Si un permiso se siente exagerado para la función del sitio, sospecha sin miedo.",
  "Menos clics impulsivos, más calma digital. CybFox está para ayudarte a pensar.",
  "Si un dominio se ve inventado o desordenado, no lo trates como si fuera legítimo.",
  "Los ciberdelincuentes son insistentes; tú debes ser más necio todavía.",
  "Desconfía de correos de ‘Soporte Técnico’ que aparecen de la nada pidiéndote datos.",
  "La intuición salva más que muchos protocolos de seguridad. Escúchala.",
  "Si el enlace está mal escrito, con números raros o letras duplicadas, corre. Es un clon.",
  "CybFox revisa lo que tus ojos pueden pasar por alto. Déjalo ayudarte.",
  "Todo lo urgente en la web es sospechoso: las estafas siempre llevan prisa.",
  "Recuerda: ningún banco del mundo te pedirá contraseñas por correo o WhatsApp.",
  "Las ventanas emergentes exageradas siempre mienten. Siempre.",
  "Protege tus datos como proteges la contraseña del WiFi de tu casa.",
  "Si la página se ve hecha a la carrera, tal vez también fue hecha para engañar rápido.",
  "Un diseño feo no siempre es mala intención, pero muchas veces sí indica descuido… o algo peor.",
  "La seguridad empieza antes del clic. Piensa antes de entrar a cualquier lado.",
  "Un enlace verificado te da un día más tranquilo. Uno dudoso te arruina la mañana.",
  "CybFox te cuida, pero tú también tienes que poner de tu parte. Equipo es equipo.",
  "Cuando tengas duda, no hagas clic. La duda te está intentando salvar.",
  "Recuerda que eres una gran persona no te dejes perder a ti mismo por cosas pequeñas. Te quiere Team CybFox"
];


  let tip = tips[Math.floor(Math.random() * tips.length)];
</script>

<div class="tip-card" role="note" aria-label="Consejo de seguridad">
  <div class="tip-inner">
    <h3 class="tip-title">Consejo de seguridad</h3>
    <p class="tip-text">{tip}</p>
  </div>
</div>

<style>
  /* ===========================
     MODO OSCURO (default)
     =========================== */
  .tip-card {
    margin-top: 16px;
    border-radius: 16px;
    padding: 14px 16px;
    cursor: default;

    background: linear-gradient(
      110deg,
      #0b1120 0%,
      #1e2631 45%,
      #0b1120 55%,
      #0b1120 100%
    );
    background-size: 200% 100%;
    animation: shine 2.6s linear infinite;

    border: 1px solid rgba(148, 163, 184, 0.4);
    box-shadow: 0 0 22px rgba(59, 130, 246, 0.4);
  }

  .tip-title {
    color: #e2e8f0;
    font-size: 1rem;
    font-weight: 600;
    margin: 0;
  }

  .tip-text {
    color: #94a3b8;
    font-size: 0.85rem;
    line-height: 1.4;
    margin: 0;
  }

  @keyframes shine {
    from { background-position: 0 0; }
    to   { background-position: -200% 0; }
  }

  /* ===========================
     MODO CLARO
     =========================== */
  :global(html[data-theme="light"]) .tip-card {
    background: linear-gradient(
      110deg,
      #f0f9ff 0%,
      #ffffff 45%,
      #f0f9ff 55%,
      #e2e8f0 100%
    );
    background-size: 200% 100%;
    animation: shine 2.6s linear infinite;

    border: 1px solid #cbd5e1;
    box-shadow: 0 6px 18px rgba(15, 23, 42, 0.06);
  }

  :global(html[data-theme="light"]) .tip-title {
    color: #0f172a;
  }

  :global(html[data-theme="light"]) .tip-text {
    color: #475569;
  }
</style>