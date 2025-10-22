const API_BASE_URL = "http://localhost:3000/api";

// Helper function to display results
function displayResult(content, type = "info") {
  const resultDiv = document.getElementById("result");
  resultDiv.textContent = content;
  resultDiv.className = type;
}

// Helper function to make API calls
async function makeApiCall(endpoint, method = "GET", data = null) {
  const resultDiv = document.getElementById("result");
  resultDiv.className = "loading";
  displayResult("Loading...", "loading");

  try {
    const options = {
      method: method,
      headers: {
        "Content-Type": "application/json",
      },
    };

    if (data) {
      options.body = JSON.stringify(data);
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.error || "API call failed");
    }

    return result;
  } catch (error) {
    displayResult(`Error: ${error.message}`, "error");
    throw error;
  }
}

// Original URL print functionality
document.getElementById("checkBtn").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    let url = tabs[0].url;
    displayResult(JSON.stringify(url), "info");
  });
});

// Test API connectivity
document.getElementById("testApiBtn").addEventListener("click", async () => {
  try {
    const result = await makeApiCall("/test");
    displayResult(`✅ ${result.message}\nTime: ${result.timestamp}`, "success");
  } catch (error) {
    // Error already handled in makeApiCall
  }
});

// Invert current URL
document.getElementById("invertUrlBtn").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    try {
      const currentUrl = tabs[0].url;

      // Encode the URL as a query parameter
      const encodedUrl = encodeURIComponent(currentUrl);
      const result = await makeApiCall(`/invert-url?url=${encodedUrl}`, "GET");

      displayResult(
        `Original: ${result.originalUrl}\n\nInverted: ${result.invertedUrl}`,
        "success"
      );
    } catch (error) {
      // Error already handled in makeApiCall
    }
  });
});

// Invert current URL
document.getElementById("getIPQS").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    try {
      const currentUrl = tabs[0].url;

      // Encode the URL as a query parameter
      const encodedUrl = encodeURIComponent(currentUrl);
      const result = await makeApiCall(`/check-ipqs?url=${encodedUrl}`, "GET");

      displayResult(
        `Unsafe: ${result.unsafe}\n Risk_score: ${result.risk_score}`,
        "success"
      );
    } catch (error) {
      // Error already handled in makeApiCall
    }
  });
});
