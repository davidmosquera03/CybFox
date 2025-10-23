function formatIPQSResponse(data) {
  return {
    unsafe: data.unsafe,
    risk_score: data.risk_score,
    root_domain: data.root_domain,
    category: data.category,
    threats: {
      spamming: data.spamming,
      malware: data.malware,
      phishing: data.phishing,
      suspicious: data.suspicious,
      adult: data.adult,
    },
  };
}

module.exports = { formatIPQSResponse };
