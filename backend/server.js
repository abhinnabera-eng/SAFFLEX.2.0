
const express = require("express");
const cors = require("cors");

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

app.post("/api/scan", async (req, res) => {
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
      parsedURL.username ||
      parsedURL.password
    ) {
      return res.status(400).json({
        verdict: "unable_to_scan",
        message: "Only valid HTTP and HTTPS URLs are accepted."
      });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    let response;

    try {
      const params = new URLSearchParams();
      params.append("url", parsedURL.href);
      params.append("format", "json");

      response = await fetch(
        "https://checkurl.phishtank.com/checkurl/",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "SAFFLEX-LinkSafety/1.0"
          },
          body: params.toString(),
          signal: controller.signal
        }
      );
    } finally {
      clearTimeout(timeout);
    }
if (!response.ok) {
  const errorDetails = await response.text();

  console.error(
    "PhishTank returned HTTP status:",
    response.status
  );

  console.error("PhishTank error details:", errorDetails);

  throw new Error("PhishTank request failed");
}

    const data = await response.json();
    const result = data.results;

    if (!result) {
      throw new Error("Unexpected PhishTank response");
    }

    const verified =
      result.verified === "y" || result.verified === true;

    const valid =
      result.valid === "y" || result.valid === true;

    if (
      result.in_database === true &&
      verified &&
      valid
    ) {
      return res.json({
        verdict: "dangerous",
        riskScore: 100,
        reasonCodes: ["known_phishing"],
        message: "A verified phishing URL was found."
      });
    }

    return res.json({
      verdict: "no_known_threat",
      riskScore: null,
      reasonCodes: [],
      message:
        "No verified phishing match was found. This does not guarantee safety."
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
