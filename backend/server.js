
const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.GOOGLE_WEBRISK_API_KEY;

// Replace YOUR-USERNAME with your actual GitHub username.
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

app.post("/api/scan", async (req, res) => {
  try {
    const { url } = req.body || {};

    // Validate input
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
      parsedURL.username ||
      parsedURL.password
    ) {
      return res.status(400).json({
        verdict: "unable_to_scan",
        message: "Only valid HTTP and HTTPS URLs are accepted."
      });
    }

    if (!API_KEY) {
      return res.status(503).json({
        verdict: "unable_to_scan",
        message: "Threat detection is not configured."
      });
    }

    // Prepare Google Web Risk request
    const params = new URLSearchParams();
    params.append("uri", url);
    params.append("threatTypes", "SOCIAL_ENGINEERING");
    params.append("threatTypes", "MALWARE");
    params.append("threatTypes", "UNWANTED_SOFTWARE");
    params.append("key", API_KEY);

    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      8000
    );

    let response;

    try {
      response = await fetch(
        "https://webrisk.googleapis.com/v1/uris:search?" +
          params.toString(),
        {
          method: "GET",
          signal: controller.signal
        }
      );
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
  const errorDetails = await response.text();

  console.error(
    `Web Risk API returned ${response.status}: ${errorDetails}`
  );

  throw new Error(
    `Threat provider request failed (${response.status})`
  );
}
    const data = await response.json();

    // Google returns threatTypes inside data.threat
    const matchedTypes = data.threat?.threatTypes || [];

    const reasonMap = {
      SOCIAL_ENGINEERING: "known_phishing",
      MALWARE: "known_malware",
      UNWANTED_SOFTWARE: "unwanted_software"
    };

    const reasonCodes = matchedTypes
      .map(type => reasonMap[type])
      .filter(Boolean);

    if (reasonCodes.length > 0) {
      return res.json({
        verdict: "dangerous",
        riskScore: 100,
        reasonCodes,
        message: "A known threat was identified."
      });
    }

    return res.json({
      verdict: "no_known_threat",
      riskScore: null,
      reasonCodes: [],
      message:
        "No known threat was found in this check. This does not guarantee safety."
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
