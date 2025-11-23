const express = require("express");
const router = express.Router();
const { extractDomain } = require("../utils/helpers");
const Page = require("../models/Page");

// Routes related to editing the MongoDB db

// Check if page is blacklisted
router.get("/check-blacklist/:url", async (req, res) => {
  // #swagger.tags = ['Database']
  // #swagger.description = 'Returns whether a page has been blacklisted'
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

// Get all blacklisted pages
router.get("/get-blacklist", async (req, res) => {
  // #swagger.tags = ['Database']
  // #swagger.description = 'Returns all blacklisted pages'
  const blacklisted = await Page.find({ isBlacklisted: true });
  res.json({
    success: true,
    count: blacklisted.length,
    blacklist: blacklisted.map((page) => ({
      url: page.url,
      blacklistedAt: page.blacklistedAt,
      currentScore: page.currentScore,
      tags: page.tags,
    })),
  });
});

// Toggle blacklist status
router.post("/toggle-blacklist", async (req, res) => {
  // #swagger.tags = ['Database']
  // #swagger.description = 'Toggles the blacklist status of a page'
  const { url } = req.body;
  const domain = extractDomain(url);

  if (!domain) {
    return res.status(400).json({ success: false, message: "Invalid URL" });
  }

  const page = await Page.findOne({ url: domain });

  if (!page) {
    await Page.create({
      url: domain,
      isBlacklisted: true,
      blacklistedAt: new Date(),
    });
    return res.json({ success: true, isBlacklisted: true });
  }

  page.isBlacklisted = !page.isBlacklisted;
  page.blacklistedAt = page.isBlacklisted ? new Date() : null;
  await page.save();

  res.json({ success: true, isBlacklisted: page.isBlacklisted });
});

// Add tags to page
router.post("/add-tag", async (req, res) => {
  // #swagger.tags = ['Database']
  // #swagger.description = 'Adds tags to a page'
  const { url, tags } = req.body;

  if (!url || !tags || !Array.isArray(tags)) {
    return res.status(400).json({
      success: false,
      message: "url and tags array required",
    });
  }

  const validTags = [
    "phishing",
    "malware",
    "publicidades intrusivas",
    "desinformación",
  ];
  const invalidTags = tags.filter((t) => !validTags.includes(t));

  if (invalidTags.length > 0) {
    return res.status(400).json({
      success: false,
      message: `Invalid tags: ${invalidTags.join(", ")}`,
      validTags,
    });
  }

  const domain = extractDomain(url);
  if (!domain) {
    return res.status(400).json({ success: false, message: "Invalid URL" });
  }

  const page = await Page.findOne({ url: domain });

  if (page) {
    page.tags = [...new Set([...page.tags, ...tags])];
    await page.save();
  } else {
    await Page.create({
      url: domain,
      tags: tags,
      reports: [],
    });
  }

  res.json({ success: true, domain, tagsAdded: tags });
});

// Remove tags from page
router.post("/remove-tag", async (req, res) => {
  // #swagger.tags = ['Database']
  // #swagger.description = 'Removes tags from a page'
  const { url, tags } = req.body;

  if (!url || !tags || !Array.isArray(tags)) {
    return res.status(400).json({
      success: false,
      message: "url and tags array required",
    });
  }

  const domain = extractDomain(url);
  if (!domain) {
    return res.status(400).json({ success: false, message: "Invalid URL" });
  }

  const page = await Page.findOne({ url: domain });

  if (!page) {
    return res.status(404).json({
      success: false,
      message: "Page not found in database",
    });
  }

  page.tags = page.tags.filter((t) => !tags.includes(t));
  await page.save();

  res.json({
    success: true,
    domain,
    tagsRemoved: tags,
    remainingTags: page.tags,
  });
});

// Get all pages with domains and scores
router.get("/get-all-pages", async (req, res) => {
  // #swagger.tags = ['Database']
  // #swagger.description = 'Returns all pages with domain and score'
  const pages = await Page.find({}, { url: 1, currentScore: 1, _id: 0 });
  res.json({
    success: true,
    count: pages.length,
    pages: pages,
  });
});

// Get single page info
router.get("/get-page/:url", async (req, res) => {
  // #swagger.tags = ['Database']
  // #swagger.description = 'Returns single page info'
  const url = decodeURIComponent(req.params.url);
  const domain = extractDomain(url);

  if (!domain) {
    return res.status(400).json({ success: false, message: "Invalid URL" });
  }

  const page = await Page.findOne({ url: domain });

  if (!page) {
    return res.status(404).json({
      success: false,
      message: "Page not found",
    });
  }

  res.json({
    success: true,
    page: {
      url: page.url,
      lastScanned: page.lastScanned,
      currentScore: page.currentScore,
      isBlacklisted: page.isBlacklisted,
      isWhitelisted: page.isWhitelisted,
      tags: page.tags,
      reports: page.reports,
    },
  });
});

// // Set (overwrite) tags for a page
// router.post("/set-tags", async (req, res) => {
//   const { url, tags } = req.body;

//   if (!url || !Array.isArray(tags)) {
//     return res.status(400).json({
//       success: false,
//       message: "url and tags array required",
//     });
//   }

//   const domain = extractDomain(url);
//   if (!domain) {
//     return res.status(400).json({ success: false, message: "Invalid URL" });
//   }

//   let page = await Page.findOne({ url: domain });

//   if (!page) {
//     page = await Page.create({
//       url: domain,
//       tags,
//       reports: [],
//     });
//   } else {
//     page.tags = tags;
//     await page.save();
//   }

//   res.json({
//     success: true,
//     domain,
//     tags,
//   });
// });


// WHITELIST
router.get("/check-whitelist/:url", async (req, res) => {
  // #swagger.tags = ['Database']
  // #swagger.description = 'Returns whether a page has been whitelisted'
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
      isWhitelisted: false,
      inDatabase: false,
      message: "Page not scanned yet",
    });
  }

  res.json({
    success: true,
    isWhitelisted: page.isWhitelisted || false,
    currentScore: page.currentScore,
    inDatabase: true,
  });
});

// Get all whitelisted pages
router.get("/get-whitelist", async (req, res) => {
  // #swagger.tags = ['Database']
  // #swagger.description = 'Returns all whitelisted pages'
  const whitelisted = await Page.find({ isWhitelisted: true });
  res.json({
    success: true,
    count: whitelisted.length,
    whitelist: whitelisted.map((page) => ({
      url: page.url,
      whitelistedAt: page.whitelistedAt,
      currentScore: page.currentScore,
      tags: page.tags,
    })),
  });
});


// ESTO ES NUEVOOO OJOOOOOOOOOO 
// Toggle whitelist status
router.post("/toggle-whitelist", async (req, res) => {
  // #swagger.tags = ['Database']
  // #swagger.description = 'Toggles the whitelist status of a page'
  const { url } = req.body;
  const domain = extractDomain(url);

  if (!domain) {
    return res.status(400).json({ success: false, message: "Invalid URL" });
  }

  const page = await Page.findOne({ url: domain });

  if (!page) {
    await Page.create({
      url: domain,
      isWhitelisted: true,
      whitelistedAt: new Date(),
    });
    return res.json({ success: true, isWhitelisted: true });
  }

  // Check if blacklisted
  if (page.isBlacklisted) {
    return res.status(400).json({
      success: false,
      message:
        "Cannot whitelist a blacklisted page. Remove from blacklist first.",
    });
  }

  page.isWhitelisted = !page.isWhitelisted;
  page.whitelistedAt = page.isWhitelisted ? new Date() : null;
  await page.save();

  res.json({ success: true, isWhitelisted: page.isWhitelisted });
});

// =======================
// SET TAGS (máx. 5 por página)
// =======================

router.post("/set-tags", async (req, res) => {
  // #swagger.tags = ['Database']
  // #swagger.description = 'Reemplaza el arreglo completo de tags de una página (máx. 5)'

  try {
    const { url, tags } = req.body;

    if (!url || !Array.isArray(tags)) {
      return res.status(400).json({
        success: false,
        message: "Se requieren 'url' y 'tags' (array).",
      });
    }

    // Limitar a 5 tags y quitar duplicados
    const uniqueTags = [...new Set(tags)].slice(0, 5);

    // Si por alguna razón llega vacío, lo permitimos (borra etiquetas)
    const domain = extractDomain(url);
    if (!domain) {
      return res.status(400).json({
        success: false,
        message: "URL inválida.",
      });
    }

    // Buscar página por dominio
    let page = await Page.findOne({ url: domain });

    if (!page) {
      // Si no existe, se crea
      page = await Page.create({
        url: domain,
        tags: uniqueTags,
        reports: [],
      });
    } else {
      // Si existe, se reemplaza el arreglo completo de tags
      page.tags = uniqueTags;
      await page.save();
    }

    return res.json({
      success: true,
      domain,
      tags: page.tags,
    });
  } catch (err) {
    console.error("[CybFox] Error en /set-tags:", err);
    return res.status(500).json({
      success: false,
      message: "Error interno al guardar etiquetas.",
      error: String(err),
    });
  }
});



module.exports = router;
