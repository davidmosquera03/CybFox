const express = require("express");
const dotenv = require("dotenv");
const Page = require("../models/Page");
const { buildPrompt } = require("../lib/buildPrompt.js");

dotenv.config();

const router = express.Router();

/* =======================================================
   1. RUTA /explain-ipqs  (la mantengo intacta pero optimizada)
======================================================= */
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

      const domain = (() => {
        try {
          return new URL(url).hostname;
        } catch {
          return url.replace(/https?:\/\//, "").split("/")[0];
        }
      })();

      const page = await Page.findOne({ url: domain });

      if (!page) {
        return res.status(404).json({
          success: false,
          message: "No se encontró un reporte IPQS para ese dominio.",
        });
      }

      const ipqsEntry = (page.reports || []).find((r) => r.source === "IPQS");

      if (!ipqsEntry) {
        return res.status(404).json({
          success: false,
          message: "No hay reporte IPQS en 'reports'.",
        });
      }

      report = ipqsEntry.data;
    }

    const prompt = generateIPQSPrompt(report);
    const apiKey = process.env.GEMINI_API_KEY;

    const gResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.2,
            maxOutputTokens: 4000,
          },
        }),
      }
    );

    if (!gResponse.ok) {
      const txt = await gResponse.text();
      return res.status(502).json({
        success: false,
        error: "Gemini error",
        details: txt,
      });
    }

    const gData = await gResponse.json();

    const explanation =
      gData?.candidates?.[0]?.content?.parts
        ?.map((p) => p.text || "")
        .join("\n")
        .trim() ||
      gData?.candidates?.[0]?.content?.text ||
      "No se recibió texto de Gemini.";

    return res.json({
      success: true,
      explanation,
      raw: gData,
    });
  } catch (err) {
    console.error("Error en /assistant/explain-ipqs:", err);
    return res.status(500).json({
      success: false,
      error: "Error interno.",
    });
  }
});

/* =======================================================
   2. RUTA /chat (MODOS + DASHBOARD + CLASES)
======================================================= */
router.post("/chat", async (req, res) => {
  try {
    const { message, history = [], mode, dashboard } = req.body;

    if (!message)
      return res.status(400).json({
        success: false,
        message: "Falta 'message'",
      });

    if (!mode)
      return res.status(400).json({
        success: false,
        message: "Falta 'mode'",
      });

    const apiKey = process.env.GEMINI_API_KEY;

    // Construimos el prompt con los 4 modos + dashboard
    const prompt = buildPrompt({
      mode,
      dashboard,
      userMessage: message,
    });

    const contents = [];

    // Incluir historial
    for (const msg of history) {
      contents.push({
        role: msg.role,
        parts: [{ text: msg.text }],
      });
    }

    // Mensaje actual
    contents.push({
      role: "user",
      parts: [{ text: prompt }],
    });

    // Llamada a Gemini
    const gResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents,
          generationConfig: {
            temperature: 0.35,
            maxOutputTokens: 4096,
          },
        }),
      }
    );

    if (!gResponse.ok) {
      const txt = await gResponse.text();
      return res.status(502).json({
        success: false,
        error: "Gemini Error",
        details: txt,
      });
    }

    const data = await gResponse.json();
    const parts = data?.candidates?.[0]?.content?.parts;

    let reply = "";

    if (Array.isArray(parts)) {
      reply = parts.map((p) => p.text || "").join("\n").trim();
    }

    if (!reply) reply = "No pude generar respuesta.";

    // Nuevo historial
    const newHistory = [
      ...history,
      { role: "user", text: message },
      { role: "model", text: reply },
    ];

    return res.json({
      success: true,
      reply,
      history: newHistory,
      raw: data,
    });
  } catch (err) {
    console.error("Error en /assistant/chat:", err);
    return res.status(500).json({
      success: false,
      error: "Error interno.",
    });
  }
});

/* =======================================================
   3. Helper para IPQS (igual)
======================================================= */
function generateIPQSPrompt(report) {
  const score = report?.score ?? report?.risk_score ?? "N/A";
  const risk = report?.riskLevel ?? report?.classification ?? "";
  const flags = Array.isArray(report?.flags)
    ? report.flags.join(", ")
    : report?.flags || "";
  const detail = report?.details || JSON.stringify(report);

  return `
Eres CybFox, un asistente pedagógico de ciberseguridad.

IPQS Score: ${score}
Nivel: ${risk}
Flags: ${flags}

Detalle:
${detail}

Explica:
1. Resumen claro (3 líneas)
2. Razones en bullets
3. Recomendaciones prácticas
  `;
}

module.exports = router;
