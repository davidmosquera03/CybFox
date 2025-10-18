const express = require("express");
const router = express.Router();
const axios = require("axios");

const qs = require("qs");
const IPQS_API_KEY = process.env.IPQS_KEY;
const VT_API_KEY = process.env.VT_KEY;
const GOOGLE_KEY = process.env.GOOGLE_KEY;

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
router.get("/check-ipqs", async (req, res) => {
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

router.get("/check-crt", async (req, res) => {
  const targetDomain = req.query.url;

  if (!targetDomain) {
    return res.status(400).json({
      success: false,
      message:
        "Missing 'url' query parameter. Usage: /check-crt?url=example.com",
    });
  }

  console.log(`Fetching certificate data for: ${targetDomain}`);

  try {
    // crt.sh JSON output endpoint
    const resp = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(targetDomain)}&output=json`
    );

    if (!resp.ok) {
      return res.status(502).json({
        success: false,
        message: `crt.sh returned status ${resp.status}`,
      });
    }

    const data = await resp.json();

    if (data.length === 0) {
      return res.status(404).json({
        success: false,
        message: "No certificates found for this domain.",
      });
    }

    res.status(200).json({
      success: true,
      count: data.length,
      certificates: data.slice(0, 5), // optional: limit results
    });
  } catch (err) {
    console.error("Error fetching from crt.sh:", err);
    res.status(500).json({
      success: false,
      message: "Error querying crt.sh",
      error: err.message,
    });
  }
});

router.get("/check-vt", async (req, res) => {
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

router.get("/check-google/:url", async (req, res) => {
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

module.exports = router;
