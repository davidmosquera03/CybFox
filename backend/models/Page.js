// models/Page.js
const mongoose = require("mongoose");

const pageSchema = new mongoose.Schema({
  url: { type: String, required: true, unique: true },
  currentScore: Number,
  isBlacklisted: { type: Boolean, default: false },
  blacklistedAt: Date,
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
