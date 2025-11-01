// models/Page.js
const mongoose = require("mongoose");

const pageSchema = new mongoose.Schema({
  url: { type: String, required: true, unique: true },
  currentScore: Number,
  lastScanned: Date,
  isBlacklisted: { type: Boolean, default: false },
  isWhitelisted: { type: Boolean, default: false }, // NEW
  blacklistedAt: Date,
  whitelistedAt: Date, // NEW
  tags: [String],
  reports: [
    {
      date: Date,
      source: String, // "IPQS", "VirusTotal", etc.
      data: Object,
    },
  ],
});

const Page = mongoose.model("Page", pageSchema);
module.exports = Page;
