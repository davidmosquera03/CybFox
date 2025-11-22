const express = require("express");
const Page = require("../models/Page");
const dotenv = require("dotenv");
dotenv.config();

const router = express.Router();

router.post("/explain-ipqs", async (req, res) => {
  try {
    const { url, ipqsReport } = req.body;

    let report = ipqsReport;

    if (!report) {
      if (!url) {
        return res.status(400).json({
          success: false,
          message: "Enviar 'url' o 'ipqsReport' en el body.",
        });
      }

      const domain = (u => {
        try {
          const parsed = new URL(u);
          return parsed.hostname;
        } catch {
          return u.replace(/https?:\/\//, "").split("/")[0];
        }
      })(url);

      const page = await Page.findOne({ url: domain });
      if (!page) {
        return res.status(404).json({
          success: false,
          message: "No se encontró un reporte IPQS para ese dominio.",
        });
      }

      const ipqsEntry = (page.reports || []).find(r => r.source === "IPQS");
      if (!ipqsEntry) {
        return res.status(404).json({
          success: false,
          message: "No se encontró un reporte IPQS en los 'reports'.",
        });
      }

      report = ipqsEntry.data;
    }

    const prompt = generateIPQSPrompt(report);

    // GEMINI
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({
        success: false,
        error: "Falta GEMINI_API_KEY",
      });
    }

const gResponse = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            contents: [{
                parts: [{
                    text: prompt
                }]
            }],
            generationConfig: {
                temperature: 0.2,
                maxOutputTokens: 2048
            },
            safetySettings: [{
                    category: "HARM_CATEGORY_DANGEROUS_CONTENT",
                    threshold: "BLOCK_NONE"
                },
                {
                    category: "HARM_CATEGORY_HARASSMENT",
                    threshold: "BLOCK_NONE"
                },
                {
                    category: "HARM_CATEGORY_HATE_SPEECH",
                    threshold: "BLOCK_NONE"
                }
            ]
        })
    }
);

    if (!gResponse.ok) {
      const txt = await gResponse.text();
      console.error("Gemini error:", txt);
      return res.status(502).json({
        success: false,
        error: "Error al comunicarse con Gemini",
        details: txt
      });
    }

    const gData = await gResponse.json();

    let explanation =
      gData?.candidates?.[0]?.content?.parts
        ?.map(p => p.text || "")
        .join("\n")
        .trim()
      || gData?.candidates?.[0]?.content?.text
      || "";

    if (!explanation) {
      explanation =
        "No se recibió texto de Gemini. Respuesta RAW:\n" +
        JSON.stringify(gData, null, 2);
    }

    return res.json({
      success: true,
      explanation,
      raw: gData
    });

  } catch (err) {
    console.error("Error in /assistant/explain-ipqs:", err);
    return res.status(500).json({
      success: false,
      error: "Error interno al generar explicación."
    });
  }
});

function generateIPQSPrompt(report) {
  const score = report?.score ?? report?.risk_score ?? "Desconocido";
  const riskLevel = report?.riskLevel ?? report?.classification ?? "";
  const flags = Array.isArray(report?.flags)
    ? report.flags.join(", ")
    : (report?.flags || "");
  const details = report?.details || JSON.stringify(report);

  return `
Eres un asistente pedagógico de ciberseguridad que explica en lenguaje simple
si una web es segura o peligrosa.

- Score/IPQS: ${score}
- Nivel o clasificación: ${riskLevel}
- Flags: ${flags}
- Detalle técnico: ${details}

Responde:
1) Explicación clara en 6–8 líneas.
2) Bullets con razones.
3) Bullets con recomendaciones prácticas.
4) Si faltan datos, dilo en una línea.
  `.trim();
}

module.exports = router;



router.post("/chat", async (req, res) => {
  try {
    const { message, history = [] } = req.body;

    if (!message) {
      return res.status(400).json({
        success: false,
        message: "Falta el campo 'message'."
      });
    }

    const apiKey = process.env.GEMINI_API_KEY;

    const contents = [];

    contents.push({
        role: "user",
            parts: [{
                text: `
    Eres un asistente experto en ciberseguridad web.
    Responde súper directo, claro y breve.
    Siempre entrega frases completas y nunca termines una oración a medias.
    Si te piden definiciones, explícalas en máximo 3 líneas.
    Si te piden recomendaciones, dales bullets cortos.
    Habla como alguien joven, relajado, sin tecnicismos innecesarios.
    `
            }]
        }
    );
for (const msg of history) {
  contents.push({
    role: msg.role,
    parts: [{ text: msg.text }]
  });
}


contents.push({
    role: "user",
    parts: [{
        text: message
    }]
});

    // Llamada a Gemini
   const gResponse = await fetch(
       `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`, {
           method: "POST",
           headers: {
               "Content-Type": "application/json"
           },
           body: JSON.stringify({
               contents,
               generationConfig: {
                   temperature: 0.3,
                   maxOutputTokens: 2048
               }
           })
       }
   );


    if (!gResponse.ok) {
      const t = await gResponse.text();
      return res.status(500).json({ success: false, error: t });
    }

    const data = await gResponse.json();

    const parts = data?.candidates?.[0]?.content?.parts;
    let reply = "";

    if (Array.isArray(parts)) {
      reply = parts.map(p => p.text || "").join("\n").trim();
    }

    if (!reply) reply = "No pude generar respuesta.";

    // Nuevo historial
    const newHistory = [
      ...history,
      { role: "user", text: message },
      { role: "model", text: reply }
    ];

    return res.json({
      success: true,
      reply,
      history: newHistory,
      raw: data
    });

  } catch (err) {
    console.error("Error en /assistant/chat:", err);
    return res.status(500).json({
      success: false,
      error: "Error interno."
    });
  }
});

