const express = require("express");
const router = express.Router();

router.get("/test", (req, res) => {
  res.json({
    message: "Backend is working!",
    timestamp: new Date().toISOString(),
  });
});

router.get("/invert-url", (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "URL is required" });
  res.json({ originalUrl: url, invertedUrl: url.split("").reverse().join("") });
});

module.exports = router;
