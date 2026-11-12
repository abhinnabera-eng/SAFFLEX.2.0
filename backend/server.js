
const express = require("express");
const cors = require("cors");
const { isIP } = require("node:net");

const app = express();
const PORT = process.env.PORT || 10000;

const allowedOrigins = [
  "https://abhinnabera-eng.github.io"
];

app.use(express.json({ limit: "10kb" }));

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origin not allowed"));
  }
}));

app.get("/", (req, res) => {
  res.json({
    message: "SAFFLEX API is running"
  });
});

// Analyse URL patterns without visiting the submitted website.
function analyseURL(parsedURL) {
  const reasons = [];
  let score = 0;

  const hostname = parsedURL.hostname.toLowerCase();
  const cleanHostname = hostname.replace(/^\[|\]$/g, "");

  // 1. Check whether the URL uses an IP address instead of a domain.
  if (isIP(cleanHostname)) {
    reasons.push("ip_address_host");
    score += 35;
  }

  // 2. Check for internationalised/punycode domains.
  if (hostname.split(".").some(label => label.startsWith("xn--"))) {
    reasons.push("punycode_domain");
    score += 30;
  }

  // 3. Check for an unusually deep subdomain structure.
  const labels = hostname.split(".").filter(Boolean);

  if (labels.length > 4) {
    reasons.push("many_subdomains");
    score += 15;
  }

  // 4. Check for unusual ports.
  if (parsedURL.port) {
    reasons.push("unusual_port");
    score += 20;
  }

  // 5. Look for potentially sensitive words in the host or path.
  // These words alone do NOT prove a link is malicious.
  const textToCheck = hostname + parsedURL.pathname;

  const suspiciousWords =
    /(login|signin|verify|password|wallet|billing|payment|account|update)/i;

  if (suspiciousWords.test(textToCheck)) {
    reasons.push("sensitive_keyword");
    score += 10;
  }

  // 6. Check for an unusually large number of query parameters.
  const parameterCount = [...parsedURL.searchParams.keys()].length;

  if (parameterCount > 8) {
    reasons.push("many_query_parameters");
    score += 5;
  }

  // 7. Check for unusually long URLs.
  if (parsedURL.href.length > 300) {
    reasons.push("long_url");
    score += 5;
  }

  return {
    score: Math.min(score, 100),
    reasons
  };
}

app.post("/api/scan", (req, res) => {
  try {
    const { url } = req.body || {};

    if (
      typeof url !== "string" ||
      url.length === 0 ||
      url.length > 2048
    ) {
      return res.status(400).json({
        verdict: "unable_to_scan",
        message: "Please provide a valid URL."
      });
    }

    let parsedURL;

    try {
      parsedURL = new URL(url);
    } catch {
      return res.status(400).json({
        verdict: "unable_to_scan",
        message: "The URL format is invalid."
      });
    }

    if (
      !["http:", "https:"].includes(parsedURL.protocol) ||
      !parsedURL.hostname ||
      parsedURL.username ||
      parsedURL.password
    ) {
      return res.status(400).json({
        verdict: "unable_to_scan",
        message: "Only valid HTTP and HTTPS URLs are accepted."
      });
    }

    const analysis = analyseURL(parsedURL);

    if (analysis.reasons.length > 0) {
      return res.json({
        verdict: "suspicious",
        riskScore: analysis.score,
        reasonCodes: analysis.reasons,
        analysisType: "heuristic",
        message:
          "Potentially suspicious URL patterns were detected. This is a warning, not confirmation of malicious activity."
      });
    }

    return res.json({
      verdict: "no_known_threat",
      riskScore: 0,
      reasonCodes: [],
      analysisType: "heuristic",
      message:
        "No strong URL-structure warning was detected. This does not guarantee safety. No live threat-intelligence database was checked."
    });

  } catch (error) {
    console.error("SAFFLEX scan error:", error.message);

    return res.status(503).json({
      verdict: "unable_to_scan",
      message: "The scan could not be completed. Please try again."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SAFFLEX API running on port ${PORT}`);
});
