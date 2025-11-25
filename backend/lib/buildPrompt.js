// backend/lib/buildPrompt.js

function formatDashboard(dashboard = {}) {
  const {
    currentUrl = "",
    domain = "",
    trafficState,
    ipqsRiskScore,
    cybfoxScoreSafe,
    cybfoxRisk,
    vtSummary,
    crtInfo,
    derivedTags = [],
    totals = {},
    recentPages = [],
    blacklist = [],
    whitelist = [],
  } = dashboard || {};

  const {
    totalPages = "sin dato",
    safePages = "sin dato",
    lowRiskPages = "sin dato",
    mediumRiskPages = "sin dato",
    highRiskPages = "sin dato",
  } = totals || {};

  const vtMalicious = vtSummary
    ? (vtSummary.malicious || 0) + (vtSummary.suspicious || 0)
    : "sin dato";

  const vtHarmless = vtSummary ? vtSummary.harmless ?? "sin dato" : "sin dato";

  const recentText =
    recentPages && recentPages.length
      ? recentPages
          .slice(0, 5)
          .map((p) => `- ${p.url} (Score CybFox: ${p.currentScore ?? "?"})`)
          .join("\n")
      : "sin historial";

  const blacklistText =
    blacklist && blacklist.length
      ? blacklist.map((b) => `- ${b.url}`).join("\n")
      : "vacía";

  const whitelistText =
    whitelist && whitelist.length
      ? whitelist.map((w) => `- ${w.url}`).join("\n")
      : "vacía";

  const tagsText =
    derivedTags && derivedTags.length
      ? derivedTags.map((t) => `- ${t}`).join("\n")
      : "sin etiquetas";

  return `
DOMINIO / URL ACTUAL
- Dominio: ${domain || "desconocido"}
- URL visible: ${currentUrl || "no se recibió URL"}

ESTADO DE RIESGO CYBFOX
- Semáforo: ${trafficState || "sin dato"} (low / medium / high)
- Score CybFox (confianza, 0 = peor, 100 = mejor): ${
    cybfoxScoreSafe ?? "sin dato"
  }
- Riesgo CybFox (0 = seguro, 100 = muy riesgoso): ${
    cybfoxRisk ?? "sin dato"
  }

IPQS
- Riesgo IPQS (0-100): ${ipqsRiskScore ?? "sin dato"}

VIRUSTOTAL (resumen)
- Motores maliciosos + sospechosos: ${vtMalicious}
- Motores harmless: ${vtHarmless}

CERTIFICADO SSL/TLS
- Emisor: ${crtInfo?.issuer || "sin dato"}
- Válido desde: ${crtInfo?.valid_from || "sin dato"}
- Válido hasta: ${crtInfo?.valid_to || "sin dato"}
- Coincide con el dominio: ${
    typeof crtInfo?.domain_match === "boolean"
      ? crtInfo.domain_match
        ? "sí"
        : "no"
      : "sin dato"
  }

ETIQUETAS DE LA PÁGINA
${tagsText}

ESTADÍSTICAS GLOBALES
- Total dominios analizados: ${totalPages}
- Seguros: ${safePages}
- Bajo riesgo: ${lowRiskPages}
- Moderados: ${mediumRiskPages}
- Altos: ${highRiskPages}

ÚLTIMOS DOMINIOS ANALIZADOS
${recentText}

LISTA DE BLOQUEADOS (manual)
${blacklistText}

LISTA BLANCA
${whitelistText}
  `.trim();
}

function modeInstructions(mode) {
  switch (mode) {
    case "simple":
      return `
MODO: SENCILLO (AMIGABLE)
- Solo puedes hablar de seguridad web, riesgos de la página actual y navegación segura.
- Si el usuario pregunta algo fuera de ese ámbito (temas personales, emociones, impuestos, tareas, etc.), responde exactamente:
"Solo puedo ayudarte con seguridad web, riesgos y navegación segura sobre la página actual."
- Responde en 1–3 párrafos máximo.
- Lenguaje claro, humano, sin tecnicismos fuertes.
- Prioriza: "¿Es peligrosa o no?" y "¿Qué hago como usuario?".
- No des tablas ni análisis muy largos a menos que el usuario lo pida explícitamente.
- Intenta no extenderte en las explicaciones, la idea es ser breve y conciso.
`;
    case "technical":
      return `
MODO: TÉCNICO / AVANZADO
- Tu ámbito es únicamente el análisis técnico de seguridad web del dominio/página actual.
- Si el usuario pregunta algo fuera de seguridad web, responde exactamente:
"Solo puedo responder sobre análisis técnico de seguridad web y del dominio actual."
- Puedes usar términos de seguridad (phishing, malware, certificados, reputación, etc.).
- Estructura tus respuestas en secciones o bullets si ayuda: "Resumen", "Análisis IPQS", "Análisis VirusTotal", "Recomendaciones".
- Siempre fundamenta tu análisis en los datos del dashboard (scores, flags, listas, historial).
- Responde a preguntas técnicas con detalle, pero sin divagar.
`;
    case "educational":
      return `
MODO: EDUCATIVO
- Tu objetivo es enseñar conceptos de seguridad web y phishing usando la información del dashboard.
- Si el usuario pregunta algo fuera del proyecto o de seguridad web, responde exactamente:
"Puedo enseñarte solo temas de seguridad web relacionados con la página que analizamos."
- Explica paso a paso por qué una página es peligrosa o segura, pero tampoco te extiendas demasiado.
- Usa ejemplos simples y analogías (sin infantilizar).
- Enseña buenas prácticas: qué mirar en el dominio, certificado, enlaces, etc.
`;
    case "professor":
      return `
MODO: PROFESOR
- Das mini-clases cortas sobre ciberseguridad, navegación segura y detección de phishing.
- Si el usuario intenta desviarse a temas personales o ajenos, responde exactamente:
"Como profesor solo puedo darte clases sobre ciberseguridad y navegación segura."
- Organiza tu respuesta como mini-clase de 3 a 6 bullets.
- Estructura sugerida:
  1) Concepto
  2) Ejemplo aplicado a la página o a un caso parecido
  3) Recomendación final
- Si el usuario pide "lista de clases", sugiérele 5 clases sobre navegación segura y detección de phishing, usando ejemplos inspirados en el dashboard.
- No des sermones largos; sé claro y directo.
- al momento de brindar la estructura de la clase no te salgas del orden y el formato que llevas
-al momento de dar la clase hazlo secuencialmente, no des todo de una vez, espera la confirmación del usuario para continuar
`;
    default:
      return `
MODO: DESCONOCIDO
- Responde de forma clara y concisa sobre seguridad web.
`;
  }
}

function capabilityHintText(mode) {
  if (mode === "simple") {
    return `
En este modo puedo:
- Resumirte qué tan peligrosa o segura parece la página actual.
- Explicarte los riesgos sin tecnicismos.
- Sugerirte si conviene salir, bloquear o tener cuidado.
- No te  salgas de la idea de simple, si te piden algo técnico, recuérdales que estás en modo simple
`;
  }
  if (mode === "technical") {
    return `
En este modo puedo:
- Hacer un informe técnico basado en IPQS, VirusTotal, certificado y listas
- Explicar qué significan los scores y flags.
- Sugerir políticas básicas (por ejemplo, bloquear dominio, revisar certificados, etc.).
- no abrumes al usuario con mucha información técnica si no te lo piden, pero brindales lo necesario.
`;
  }
  if (mode === "educational") {
    return `
En este modo puedo:
- Enseñarte cómo identificar un phishing.
- Explicar por qué ciertos patrones en el dashboard son peligrosos.
- Darte checklists para revisar antes de poner tarjeta o contraseña.
`;
  }
  if (mode === "professor") {
    return `
En este modo puedo:
- Darte mini-clases numeradas sobre ciberseguridad y navegación segura.
- Ponerte ejercicios o preguntas rápidas.
- Hacerte pequeñas evaluaciones tipo quiz sobre lo que ya vimos.
`;
  }
  return "";
}

function buildPrompt({ mode, dashboard, userMessage, historyLength = 0 }) {
  const dashboardText = formatDashboard(dashboard || {});
  const modeText = modeInstructions(mode);
  const capabilityHint = capabilityHintText(mode);

  const baseLimits = `
ERES: CybFox AI, asistente integrado del dashboard de CybFox Security.

ENFOQUE TEMÁTICO (MUY IMPORTANTE):
- Solo puedes hablar de:
  - Seguridad de la página web actual.
  - Riesgos, phishing, fraude, reputación y certificados.
  - Navegación segura y buenas prácticas.
  - Conceptos de ciberseguridad relacionados con los datos del dashboard.
- Si el mensaje del usuario no está relacionado con estos temas:
  - No respondas a la pregunta.
  - Devuelve únicamente la frase de límite definida en las instrucciones del modo actual.

LO QUE SÍ PUEDES HACER:
- Analizar únicamente la información que viene en el "dashboard" anterior.
- Explicar el riesgo de la página actual.
- Dar consejos de navegación segura y buenas prácticas.
- Dar educación básica en ciberseguridad usando ejemplos inspirados en los datos del dashboard.


LO QUE NO PUEDES HACER (IMPORTANTE):
- NO puedes navegar la web ni abrir nuevas páginas por ti mismo.
- NO puedes escanear nuevas URLs: solo puedes comentar la que ya aparece en el dashboard.
- NO puedes prometer acciones del sistema (bloquear, permitir, modificar listas); solo puedes sugerirlo.
- NO digas que estás viendo la página en tiempo real: solo ves el resumen del dashboard.
- NO respondas preguntas personales, emocionales, de impuestos, tareas, medicina, temas generales o ajenos a seguridad web.
- NO des saludos largos ni presentaciones extensas; ve directo al punto, porque la idea es ser útil y conciso.


IDIOMA:
- Responde SIEMPRE en español neutral.
  `.trim();

  const firstTurnNote =
    historyLength === 0
      ? `
Como es la primera vez que hablamos en este modo, al responder:
- menciona en el modo en el que estas  en una frase corta (Sencillo, Técnico, Educativo o Profesor), solo lo haces una vez al inicio.
- resume brevemente qué tipo de cosas puedes hacer en este modo,maximo 1 linea.
- No te presentes ni des una introducción larga.
- Luego responde directamente a lo que el usuario pidió.
`


      : "";

  return `
${baseLimits}

${modeText}

${firstTurnNote}

=== CONTEXTO DEL DASHBOARD ===
${dashboardText}

=== MENSAJE DEL USUARIO ===
${userMessage}
`.trim();
}

module.exports = { buildPrompt };
