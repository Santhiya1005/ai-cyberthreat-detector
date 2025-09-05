const express = require("express");
const cors = require("cors");
require("dotenv").config();
const axios = require("axios");
const mongoose = require("mongoose");
const net = require("net");
const path = require("path");

const app = express();
app.use(express.json());
app.use(cors({ origin: "*" }));

// -------------------------------
// Environment variable check
// -------------------------------
if (!process.env.VT_API_KEY || !process.env.ABUSEIPDB_KEY || !process.env.MONGO_URL) {
  console.error("❌ Missing required environment variables (.env)");
  process.exit(1);
}

// -------------------------------
// MongoDB connection
// -------------------------------
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err.message));

// -------------------------------
// Schema & Model
// -------------------------------
const scanSchema = new mongoose.Schema({
  input: String,
  status: String,
  stats: Object,
  total_engines: Number,
  threatType: String,
  aiPrediction: String,
  detectedBy: [String],
  date: { type: Date, default: Date.now },
});
const Scan = mongoose.model("Scan", scanSchema);

// -------------------------------
// Local dataset
// -------------------------------
const maliciousData = require(path.join(__dirname, "malicious.json"));

// -------------------------------
// Helpers
// -------------------------------
function isIP(input) {
  return net.isIP(input) !== 0;
}

function isHash(input) {
  return /^[a-fA-F0-9]{32,64}$/.test(input);
}

function getStatus(maliciousCount = 0, abuseScore = 0) {
  if (maliciousCount > 3 || abuseScore > 50) return "🚨 High Threat!";
  if (maliciousCount > 0 || abuseScore > 0) return "⚠️ Suspicious!";
  return "✅ No threat found";
}

function localThreatCheck(input) {
  const val = input.trim().toLowerCase();
  const found = maliciousData.find((item) => item.value.toLowerCase() === val);

  if (found) {
    return {
      input,
      status: "🚨 High Threat!",
      stats: { malicious: 5 },
      total_engines: 1,
      threatType:
        found.type === "hash"
          ? "Malware"
          : found.type === "ip"
          ? "High Risk IP"
          : "Malware",
      detectedBy: ["LocalDB"],
    };
  }

  return {
    input,
    status: "✅ No threat found",
    stats: { malicious: 0 },
    total_engines: 1,
    threatType: "Safe",
    detectedBy: ["LocalDB"],
  };
}

// -------------------------------
// AbuseIPDB
// -------------------------------
async function checkAbuseIPDB(ip) {
  try {
    const response = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: process.env.ABUSEIPDB_KEY, Accept: "application/json" },
    });
    return response.data.data;
  } catch {
    return null;
  }
}

// -------------------------------
// VirusTotal URL
// -------------------------------
async function checkVirusTotalURL(url) {
  try {
    await axios.post(
      "https://www.virustotal.com/api/v3/urls",
      `url=${encodeURIComponent(url)}`,
      {
        headers: {
          "x-apikey": process.env.VT_API_KEY,
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const urlId = Buffer.from(url)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const vtResult = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      { headers: { "x-apikey": process.env.VT_API_KEY } }
    );

    const attributes = vtResult.data.data?.attributes;
    if (!attributes) return null;

    const stats = attributes.last_analysis_stats || {};
    const analysisResults = attributes.last_analysis_results || {};

    const detectedBy = Object.entries(analysisResults)
      .filter(([_, result]) => result.category === "malicious" || result.category === "suspicious")
      .map(([engine]) => engine);

    return { stats, detectedBy: detectedBy.length > 0 ? detectedBy : ["VirusTotal"] };
  } catch {
    return null;
  }
}

// -------------------------------
// VirusTotal Hash
// -------------------------------
async function checkVirusTotalHash(hash) {
  try {
    const vtResult = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { "x-apikey": process.env.VT_API_KEY },
    });

    const attributes = vtResult.data.data?.attributes;
    if (!attributes) return null;

    const stats = attributes.last_analysis_stats || {};
    const analysisResults = attributes.last_analysis_results || {};

    const detectedBy = Object.entries(analysisResults)
      .filter(([_, result]) => result.category === "malicious" || result.category === "suspicious")
      .map(([engine]) => engine);

    return { stats, detectedBy: detectedBy.length > 0 ? detectedBy : ["VirusTotal"] };
  } catch {
    return null;
  }
}

// -------------------------------
// AI Integration (FastAPI)
// -------------------------------
async function checkAI(url) {
  try {
    const res = await axios.post("http://127.0.0.1:8000/predict", { url });
    return res.data; // { url: "...", prediction: "phishing" }
  } catch (err) {
    console.error("❌ AI error:", err.message);
    return null;
  }
}

// -------------------------------
// Scan Route
// -------------------------------
app.post("/api/scan", async (req, res) => {
  const { input } = req.body;
  if (!input) return res.status(400).json({ message: "No input provided" });

  let result = null;

  try {
    // ---------- IP Check ----------
    if (isIP(input)) {
      const abuseResult = await checkAbuseIPDB(input);
      const score = abuseResult?.abuseConfidenceScore || 0;
      result = {
        input,
        status: getStatus(0, score),
        stats: { malicious: score },
        total_engines: 1,
        threatType: score > 0 ? "High Risk IP" : "Safe",
        detectedBy: score > 0 ? ["AbuseIPDB"] : ["SafeIPDB"],
      };
    }

    // ---------- URL Check ----------
    else if (input.startsWith("http")) {
      const vt = await checkVirusTotalURL(input);
      const localResult = localThreatCheck(input);

      const malicious = vt?.stats?.malicious || 0;
      const detectedBy = [...(vt?.detectedBy || []), ...localResult.detectedBy];

      result = {
        input,
        status:
          malicious > 0
            ? "🚨 High Threat!"
            : localResult.status !== "✅ No threat found"
            ? localResult.status
            : "✅ No threat found",
        stats: vt?.stats || localResult.stats,
        total_engines:
          Object.values(vt?.stats || {}).reduce((a, b) => a + b, 0) +
          localResult.total_engines,
        threatType:
          malicious > 0
            ? "Malware"
            : localResult.threatType !== "Safe"
            ? localResult.threatType
            : "Safe",
        detectedBy: [...new Set(detectedBy)],
      };

      // AI check
      const aiResult = await checkAI(input);
      if (aiResult?.prediction) {
        result.aiPrediction = aiResult.prediction;
        result.detectedBy.push("AI Model");

        if (aiResult.prediction.toLowerCase() === "malware") {
          result.status = "🚨 High Threat!";
          result.threatType = "Malware";
        } else if (aiResult.prediction.toLowerCase() === "phishing") {
          result.status = "⚠️ Suspicious!";
          result.threatType = "Phishing";
        }
      }
    }

    // ---------- Hash Check ----------
    else if (isHash(input)) {
      const vt = await checkVirusTotalHash(input);
      const localResult = localThreatCheck(input);

      const malicious = vt?.stats?.malicious || 0;
      const detectedBy = [...(vt?.detectedBy || []), ...localResult.detectedBy];

      result = {
        input,
        status:
          malicious > 0
            ? "🚨 High Threat!"
            : localResult.status !== "✅ No threat found"
            ? localResult.status
            : "✅ No threat found",
        stats: vt?.stats || localResult.stats,
        total_engines:
          Object.values(vt?.stats || {}).reduce((a, b) => a + b, 0) +
          localResult.total_engines,
        threatType:
          malicious > 0
            ? "Malware"
            : localResult.threatType !== "Safe"
            ? localResult.threatType
            : "Safe",
        detectedBy: [...new Set(detectedBy)],
      };
    }

    await Scan.create(result);
    res.json(result);
  } catch (err) {
    console.error("❌ Scan error:", err.message);
    res.status(500).json(localThreatCheck(input));
  }
});

// -------------------------------
// History Route
// -------------------------------
app.get("/api/history", async (req, res) => {
  try {
    const scans = await Scan.find().sort({ date: -1 }).limit(5);
    res.json(scans);
  } catch (err) {
    res.status(500).json({ error: "Error fetching history" });
  }
});

// -------------------------------
// Server
// -------------------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
