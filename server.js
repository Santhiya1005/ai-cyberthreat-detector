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

// Env check
if (!process.env.VT_API_KEY || !process.env.ABUSEIPDB_KEY || !process.env.MONGO_URL) {
  console.error("❌ Missing required environment variables (.env)");
  process.exit(1);
}

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err.message));

// Schema
const scanSchema = new mongoose.Schema({
  input: String,
  status: String,
  stats: Object,
  total_engines: Number,
  threatType: String,
  detectedBy: [String],
  date: { type: Date, default: Date.now },
});
const Scan = mongoose.model("Scan", scanSchema);

// Load local dataset
const maliciousData = require(path.join(__dirname, "malicious.json"));

// Helpers
function isIP(input) {
  return net.isIP(input) !== 0;
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
      status: "🚨 High Threat!",
      stats: { malicious: 5 },
      total_engines: 5,
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
    status: "✅ No threat found",
    stats: { malicious: 0 },
    total_engines: 5,
    threatType: "Safe",
    detectedBy: ["LocalDB"],
  };
}

// AbuseIPDB
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

// VirusTotal
async function checkVirusTotalURL(url) {
  try {
    await axios.post(
      "https://www.virustotal.com/api/v3/urls",
      `url=${url}`,
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
    const vtResult = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": process.env.VT_API_KEY },
    });
    return vtResult.data.data?.attributes?.last_analysis_stats || null;
  } catch {
    return null;
  }
}

async function checkVirusTotalHash(hash) {
  try {
    const vtResult = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { "x-apikey": process.env.VT_API_KEY },
    });
    return vtResult.data.data?.attributes?.last_analysis_stats || null;
  } catch {
    return null;
  }
}

// Scan route
app.post("/api/scan", async (req, res) => {
  const { input } = req.body;
  if (!input) return res.status(400).json({ message: "No input provided" });

  let result = null;

  try {
    // 1️⃣ Check API first
    if (isIP(input)) {
      const abuseResult = await checkAbuseIPDB(input);
      const score = abuseResult?.abuseConfidenceScore || 0;
      if (score > 0) {
        result = {
          input,
          status: getStatus(0, score),
          stats: { abuseConfidenceScore: score },
          total_engines: 1,
          threatType: score > 50 ? "High Risk IP" : "Suspicious IP",
          detectedBy: ["AbuseIPDB"],
        };
      }
    } else if (input.startsWith("http")) {
      const vtStats = await checkVirusTotalURL(input);
      if (vtStats) {
        const malicious = vtStats.malicious || 0;
        result = {
          input,
          status: getStatus(malicious),
          stats: vtStats,
          total_engines: Object.values(vtStats).reduce((a, b) => a + b, 0),
          threatType: malicious > 0 ? "Malware" : "Safe",
          detectedBy: Object.keys(vtStats).filter((k) => vtStats[k] > 0),
        };
      }
    } else {
      const vtStats = await checkVirusTotalHash(input);
      if (vtStats) {
        const malicious = vtStats.malicious || 0;
        result = {
          input,
          status: getStatus(malicious),
          stats: vtStats,
          total_engines: Object.values(vtStats).reduce((a, b) => a + b, 0),
          threatType: malicious > 0 ? "Malware" : "Safe",
          detectedBy: Object.keys(vtStats).filter((k) => vtStats[k] > 0),
        };
      }
    }

    // 2️⃣ If API result not high threat, merge local dataset
    const localResult = localThreatCheck(input);
    if (result) {
      result.total_engines += localResult.total_engines;
      result.detectedBy = [...new Set([...result.detectedBy, ...localResult.detectedBy])];
      if (result.status.includes("No threat") && !localResult.status.includes("No threat")) {
        result.status = localResult.status;
        result.threatType = localResult.threatType;
      }
    } else {
      result = localResult;
    }

    await Scan.create(result);
    res.json(result);
  } catch (err) {
    console.error("Scan error:", err.message);
    res.json(localThreatCheck(input));
  }
});

// History
app.get("/api/history", async (req, res) => {
  try {
    const scans = await Scan.find().sort({ date: -1 }).limit(5);
    res.json(scans);
  } catch (err) {
    res.status(500).json({ error: "Error fetching history" });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
