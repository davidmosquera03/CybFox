function extractDomain(url) {
  try {
    // Add protocol if missing
    const fullUrl = url.includes("://") ? url : `https://${url}`;
    const parsed = new URL(fullUrl);
    return parsed.hostname; // Returns "example.com"
  } catch (error) {
    console.error("Invalid URL:", url);
    return null;
  }
}

module.exports = { extractDomain };
