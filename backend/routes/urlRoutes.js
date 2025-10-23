const express = require("express");
const router = express.Router();
const axios = require("axios");
const qs = require("qs");
const tls = require("tls");
const { formatIPQSResponse } = require("../utils/formatters");
const { extractDomain } = require("../utils/helpers");
const Page = require("../models/Page");
// API KEYS
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
  const encodedUrl = encodeURIComponent(targetUrl);

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

router.get("/check-ipqs", async (req, res) => {
  // #swagger.tags = ['URLs']
  // #swagger.description = 'Uses IPQS API for safety info '

  // 1. Get the URL and strictness from query parameters
  const targetUrl = req.query.url;
  const domain = extractDomain(targetUrl);
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
    const formatted = formatIPQSResponse(result);

    const page = await Page.findOne({ url: domain });

    if (page) {
      // Remove old IPQS report
      page.reports = page.reports.filter((r) => r.source !== "IPQS");
      page.reports.push({ source: "IPQS", date: new Date(), data: formatted });
      page.currentScore = formatted.risk_score;
      await page.save();
    } else {
      // Create new
      await Page.create({
        url: domain,
        currentScore: formatted.risk_score,
        reports: [{ source: "IPQS", date: new Date(), data: formatted }],
      });
    }

    res.status(200).json(formatted);
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

router.get("/check-vt", async (req, res) => {
  // #swagger.tags = ['URLs']
  // #swagger.description = 'Uses Virus Total Api to see safety info '
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

// #swagger.tags = ['URLs']
router.get("/check-google/:url", async (req, res) => {
  // #swagger.tags = ['URLs']
  // #swagger.description = 'Uses Google Safe Browsing API to see if page is safe '
  try {
    const urlToCheck = decodeURIComponent(req.params.url);
    const domain = extractDomain(urlToCheck); // Fixed variable name

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

    if (!response.ok) {
      const errorData = await response.json();
      return res.status(response.status).json({
        error: "Error en Google Safe Browsing API",
        details: errorData,
      });
    }

    const data = await response.json();

    // Format response
    const formatted = {
      safe: !data.matches || data.matches.length === 0,
      threats: data.matches || [],
    };

    // Save to DB
    const page = await Page.findOne({ url: domain });

    if (page) {
      page.reports = page.reports.filter((r) => r.source !== "Google");
      page.reports.push({
        source: "Google",
        date: new Date(),
        data: formatted,
      });
      await page.save();
    } else {
      await Page.create({
        url: domain,
        reports: [{ source: "Google", date: new Date(), data: formatted }],
      });
    }

    res.json(formatted);
  } catch (error) {
    console.error("Error checking URL:", error);
    res.status(500).json({
      error: "Error al verificar la URL",
      message: error.message,
    });
  }
});

router.get("/check-crt", async (req, res) => {
  // #swagger.tags = ['URLs']
  // #swagger.description = 'Returns certificate info '
  const { domain } = req.query;
  if (!domain)
    return res
      .status(400)
      .json({ success: false, message: "Missing ?domain=" });

  try {
    const result = await new Promise((resolve) => {
      try {
        const parsed = new URL(
          domain.includes("://") ? domain : `https://${domain}`
        );
        const hostname = parsed.hostname;

        const options = {
          host: hostname,
          port: 443,
          method: "GET",
          servername: hostname,
        };

        const tlsSocket = tls.connect(options, () => {
          const cert = tlsSocket.getPeerCertificate(true);

          if (!cert || !Object.keys(cert).length) {
            resolve({
              success: false,
              message: "No certificate found (possibly HTTP only).",
            });
            tlsSocket.end();
            return;
          }

          const domainMatch =
            (cert.subject?.CN && cert.subject.CN.includes(hostname)) ||
            (cert.subjectaltname && cert.subjectaltname.includes(hostname));

          resolve({
            success: true,
            https: true,
            domain: hostname,
            valid_from: cert.valid_from,
            valid_to: cert.valid_to,
            issuer: cert.issuer ? cert.issuer.O : "Unknown",
            domain_match: !!domainMatch,
          });

          tlsSocket.end();
        });

        tlsSocket.on("error", (err) => {
          resolve({
            success: false,
            message: `Connection error or no HTTPS: ${err.message}`,
          });
        });
      } catch (err) {
        resolve({
          success: false,
          message: `Invalid domain or request error: ${err.message}`,
        });
      }
    });

    res.json(result);
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal error",
      error: error.message,
    });
  }
});

//check blacklist
router.get("/check-blacklist/:url", async (req, res) => {
  // #swagger.tags = ['URLs']
  // #swagger.description = 'returns whether a page has been blacklisted '
  const url = decodeURIComponent(req.params.url);
  const domain = extractDomain(url);

  if (!domain) {
    return res.status(400).json({
      success: false,
      message: "Invalid URL",
    });
  }

  const page = await Page.findOne({ url: domain });

  if (!page) {
    return res.json({
      success: true,
      isBlacklisted: false,
      inDatabase: false,
      message: "Page not scanned yet",
    });
  }

  res.json({
    success: true,
    isBlacklisted: page.isBlacklisted || false,
    currentScore: page.currentScore,
    inDatabase: true,
  });
});

// toggle backlist
router.post("/toggle-blacklist", async (req, res) => {
  // #swagger.tags = ['URLs']
  // #swagger.description = 'toggles the blacklist status of a page in DB '
  const { url } = req.body;
  const domain = extractDomain(url);

  if (!domain) {
    return res.status(400).json({ success: false, message: "Invalid URL" });
  }

  const page = await Page.findOne({ url: domain });

  if (!page) {
    // Create new with blacklist: true
    await Page.create({
      url: domain,
      isBlacklisted: true,
      blacklistedAt: new Date(),
    });
    return res.json({ success: true, isBlacklisted: true });
  }

  // Toggle existing
  page.isBlacklisted = !page.isBlacklisted;
  page.blacklistedAt = page.isBlacklisted ? new Date() : null;
  await page.save();

  res.json({ success: true, isBlacklisted: page.isBlacklisted });
});
//

module.exports = router;
