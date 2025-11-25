// backend/prompts/classes.js

const class1 = `
🎓 Clase 1 — Dominios sospechosos

1) Introducción
Un dominio es la "dirección" del sitio (por ejemplo: docs.github.com).
En phishing, los atacantes crean dominios muy parecidos al real o usan
direcciones recién creadas para engañar al usuario.

2) Ejemplo con esta página
- Revisa el dominio real en DASHBOARD_CONTEXT.domain.
- Comprueba si coincide con lo que esperas ver (marca, banco, servicio).
- Si el dominio es muy largo, tiene letras cambiadas o subdominios raros,
  explícaselo al usuario paso a paso.
- Usa IPQS y CybFoxScore para reforzar la explicación.

3) Pregunta rápida
Haz una pregunta sencilla, por ejemplo:
"Si una URL cambia una sola letra del dominio original de tu banco,
¿deberías confiar o desconfiar?"
Después, corrige brevemente su respuesta y refuerza la idea principal.
`;

const class2 = `
🎓 Clase 2 — Certificado SSL (el candado)

1) Introducción
El certificado SSL/TLS protege la comunicación entre el navegador y el sitio.
No garantiza que la página sea honesta, pero sí que la conexión está cifrada.

2) Ejemplo con esta página
- Usa DASHBOARD_CONTEXT.crtInfo para comentar:
  - Emisor del certificado (issuer).
  - Fechas "valid_from" y "valid_to".
  - Si "domain_match" es verdadero o falso.
- Explica por qué un certificado expirado o que no coincide con el dominio
  es una alerta importante.

3) Pregunta rápida
Pregunta algo como:
"Si el certificado está expirado o no coincide con el dominio,
¿es buena idea escribir tus datos personales ahí?"
Corrige brevemente y cierra con una recomendación clara.
`;

const class3 = `
🎓 Clase 3 — Formularios peligrosos

1) Introducción
Muchos ataques phishing usan formularios falsos para robar contraseñas,
tarjetas y datos personales.

2) Ejemplo con esta página
- A partir de las etiquetas y categoría del dashboard, explica:
  - Por qué un formulario puede ser sospechoso (URL rara, página nueva,
    mala reputación, etc.).
  - Qué tipo de datos nunca deberías poner en un sitio dudoso.
- Da 2-3 reglas simples para reconocer formularios peligrosos.

3) Pregunta rápida
Pregunta algo como:
"¿Qué revisarías antes de escribir tu tarjeta de crédito en un formulario?"
Luego refuerza 2-3 puntos clave que el usuario debería recordar.
`;

const class4 = `
🎓 Clase 4 — Señales visuales de phishing

1) Introducción
Además de los datos técnicos, las páginas falsas suelen verse "raras":
logos borrosos, botones desalineados, textos mal escritos.

2) Ejemplo con esta página
- Usa las etiquetas y categoría del dashboard para explicar:
  - Qué elementos visuales suelen delatar un phishing.
  - Por qué un sitio legítimo cuida mucho su diseño y ortografía.
- Invita al usuario a fijarse en detalles concretos antes de hacer clic.

3) Pregunta rápida
Pregúntale algo como:
"Menciona una señal visual que te haría desconfiar de un sitio web."
Refuerza su respuesta y añade 1 o 2 ejemplos más.
`;

const class5 = `
🎓 Clase 5 — Motores de reputación (IPQS / VirusTotal)

1) Introducción
Motores como IPQS y VirusTotal analizan dominios y URLs para detectar
patrones maliciosos, malware y campañas de phishing.

2) Ejemplo con esta página
- Usa DASHBOARD_CONTEXT.ipqsRiskScore, DASHBOARD_CONTEXT.ipqsData
  y DASHBOARD_CONTEXT.vtSummary para explicar:
  - Qué significa un riesgo alto/bajo.
  - Qué implica que varios motores marquen la página como maliciosa.
- Muestra un pequeño resumen tipo:

JSON:
  {
    "ipqs_score": "<valor numérico>",
    "ipqs_category": "<categoría>",
    "vt_malicious": <motores_maliciosos>,
    "vt_suspicious": <motores_sospechosos>
  }

3) Pregunta rápida
Pregunta algo como:
"Si varios motores de reputación marcan un dominio como malicioso,
¿qué acción tomarías antes de seguir navegando?"
Cierra con una recomendación clara.
`;

const classesIndex = `
Índice de clases disponibles:

1. Dominios sospechosos
2. Certificados SSL (candado)
3. Formularios peligrosos
4. Señales visuales de phishing
5. Motores de reputación (IPQS / VirusTotal)

Puedes pedir:
- "Lista de clases"
- "Dame la clase 1" (o 2, 3, 4, 5)
- "Dame una clase al azar"
- "Hazme una pregunta para practicar"
`;

const quiz = `
Modo Profesor — Pregunta rápida

Haz UNA sola pregunta sencilla sobre detección de phishing o seguridad web
relacionada con la página actual. Espera la respuesta del usuario y,
cuando la dé, respóndele con una corrección corta (1-2 frases) y un consejo.
`;

module.exports.professorClasses = {
  1: class1,
  2: class2,
  3: class3,
  4: class4,
  5: class5,
  quiz,
};

module.exports.classesIndex = classesIndex;
