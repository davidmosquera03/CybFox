require("dotenv").config();

const express = require("express");
const axios = require("axios");
const qs = require("qs");
const app = express();

const PORT = 3000;

// load from .env
const IPQS_API_KEY = process.env.IPQS_KEY;
const VT_API_KEY = process.env.VT_KEY;
const GOOGLE_KEY = process.env.GOOGLE_KEY;

app.get("/api/test", (req, res) => {
  res.json({
    message: "Backend is working!",
    timestamp: new Date().toISOString(),
  });
});

// URL inversion route
app.get("/api/invert-url", (req, res) => {
  try {
    const { url } = req.query; // Use query params instead of body

    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    const invertedUrl = url.split("").reverse().join("");

    res.json({
      originalUrl: url,
      invertedUrl: invertedUrl,
      success: true,
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

async function checkUrlReputation(targetUrl, strictness = 0) {
  if (!IPQS_API_KEY) {
    console.error("Missing IPQS API key.");
    return {
      success: false,
      message: "Missing IPQS API key",
    };
  }

  const safeStrictness = Math.max(
    0,
    Math.min(2, parseInt(strictness, 10) || 0)
  );
  const encodedUrl = encodeURIComponent(targetUrl); // ✅ correct encoding

  const apiUrl = `https://ipqualityscore.com/api/json/url/${IPQS_API_KEY}/${encodedUrl}`;

  try {
    const response = await axios.get(apiUrl, {
      params: { strictness: safeStrictness },
      timeout: 10000,
    });

    return response.data;
  } catch (error) {
    if (error.response) {
      return {
        success: false,
        message: `External API call failed. Status: ${error.response.status}`,
        details: error.response.data,
      };
    }
    return {
      success: false,
      message: "Unexpected error while calling IPQS API.",
      details: error.message,
    };
  }
}

// --- Express Route: /check-ipqs ---
app.get("/check-ipqs", async (req, res) => {
  // 1. Get the URL and strictness from query parameters
  const targetUrl = req.query.url;
  const strictness = req.query.strictness; // String, will be parsed in the function

  if (!targetUrl) {
    // 400 Bad Request if 'url' parameter is missing
    return res.status(400).json({
      success: false,
      message:
        "Missing 'url' query parameter. Usage: /check-ipqs?url=http://example.com",
    });
  }

  console.log(`Scanning URL: ${targetUrl} with strictness: ${strictness || 0}`);

  // 2. Call the IPQS function
  const result = await checkUrlReputation(targetUrl, strictness);

  // 3. Handle the response and return appropriate status codes
  if (result.success === true) {
    // Successful response from IPQS
    res.status(200).json(result);
  } else if (
    result.message &&
    result.message.includes("API Key is not configured")
  ) {
    // Forbidden status if the key is missing or invalid
    res.status(403).json(result);
  } else {
    // Generic error (e.g., timeout, unexpected API response)
    res.status(500).json(result);
  }
});

app.get("/check-crt", async (req, res) => {
  // 1. Get the URL and strictness from query parameters
  const targetUrl = req.query.url;

  if (!targetUrl) {
    // 400 Bad Request if 'url' parameter is missing
    return res.status(400).json({
      success: false,
      message:
        "Missing 'url' query parameter. Usage: /check-ipqs?url=http://example.com",
    });
  }

  console.log(`Scanning SSL of: ${targetUrl}`);

  // 2. Call the IPQS function
  const result = await checkUrlReputation(targetUrl, strictness);

  // 3. Handle the response and return appropriate status codes
  if (result.success === true) {
    // Successful response from IPQS
    res.status(200).json(result);
  } else if (
    result.message &&
    result.message.includes("API Key is not configured")
  ) {
    // Forbidden status if the key is missing or invalid
    res.status(403).json(result);
  } else {
    // Generic error (e.g., timeout, unexpected API response)
    res.status(500).json(result);
  }
});

app.get("/check-vt", async (req, res) => {
  try {
    const { url } = req.query;

    if (!url) {
      return res.status(400).json({
        success: false,
        message: "URL is required as a query parameter (?url=...).",
      });
    }

    if (!VT_API_KEY) {
      return res.status(500).json({
        success: false,
        message: "VirusTotal API key not configured (check your .env file).",
      });
    }

    // Step 1: Submit the URL for analysis
    const encodedUrl = qs.stringify({ url });
    const submitResponse = await axios.post(
      "https://www.virustotal.com/api/v3/urls",
      encodedUrl,
      {
        headers: {
          accept: "application/json",
          "x-apikey": VT_API_KEY,
          "content-type": "application/x-www-form-urlencoded",
        },
      }
    );

    // Step 2: Retrieve the analysis ID
    const analysisId = submitResponse.data.data.id;

    // Step 3: Query the analysis result
    const analysisResponse = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: {
          accept: "application/json",
          "x-apikey": VT_API_KEY,
        },
      }
    );

    res.status(200).json({
      success: true,
      analysis: analysisResponse.data,
    });
  } catch (error) {
    console.error(
      "VirusTotal API error:",
      error.response?.data || error.message
    );
    res.status(500).json({
      success: false,
      message: "Failed to retrieve VirusTotal analysis.",
      error: error.response?.data || error.message,
    });
  }
});

app.get("/check-google/:url", async (req, res) => {
  try {
    const urlToCheck = decodeURIComponent(req.params.url);

    // Validación básica de URL
    if (!urlToCheck || urlToCheck.trim() === "") {
      return res.status(400).json({ error: "URL es requerida" });
    }

    const body = {
      client: {
        clientId: "myapp",
        clientVersion: "1.0",
      },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION",
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: urlToCheck }],
      },
    };

    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }
    );

    // Manejo de errores de la API
    if (!response.ok) {
      const errorData = await response.json();
      return res.status(response.status).json({
        error: "Error en Google Safe Browsing API",
        details: errorData,
      });
    }

    const data = await response.json();

    if (data.matches && data.matches.length > 0) {
      res.json({
        safe: false,
        threats: data.matches,
        url: urlToCheck,
      });
    } else {
      res.json({
        safe: true,
        url: urlToCheck,
      });
    }
  } catch (error) {
    console.error("Error checking URL:", error);
    res.status(500).json({
      error: "Error al verificar la URL",
      message: error.message,
    });
  }
});

/* app.get("/scan/ssllabs/:host", async (req, res) => {
  const host = req.params.host;
  // v4 may require header 'email' — check docs and register if needed.
  const r = await fetch(`https://api.ssllabs.com/api/v4/analyze?host=${host}`, {
    headers: { email: "[your-email@example.com]" }, // include if required
  });
  const j = await r.json();
  res.json(j);
}); */

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Test the API at: http://localhost:${PORT}/api/test`);
});
