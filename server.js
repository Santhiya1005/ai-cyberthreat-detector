const express = require("express");
const cors = require("cors");
require("dotenv").config();
const axios = require("axios");
const mongoose = require("mongoose");
const net = require("net");

const app = express();
app.use(express.json());

app.use(
  cors({
    origin: ["http://localhost:3000"],
  })
);

// Check env
if (!process.env.VT_API_KEY || !process.env.ABUSEIPDB_KEY || !process.env.MONGO_URL) {
  console.error("❌ Missing required environment variables (.env)");
  process.exit(1);
}

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => console.error("❌ MongoDB connection error:", err.message));

// 🔹 Schema for scan history
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

// Helpers
function isIP(input) {
  return net.isIP(input) !== 0;
}

function getStatus(malicious, abuseScore = 0) {
  if (malicious > 3 || abuseScore > 50) return "🚨 High Threat!";
  if (malicious > 0 || abuseScore > 0) return "⚠️ Suspicious!";
  return "✅ No threat found";
}

// 🔹 Local threat check
function localThreatCheck(input) {
  const unsafeList = ["malware.com", "phishing-site.com", "hackme.org"];
  const suspiciousList = ["test-virus.net", "unknown.io"];
  const val = input.trim().toLowerCase();

  if (unsafeList.includes(val)) {
    return { status: "🚨 High Threat!", stats: { malicious: 5 }, total_engines: 5, threatType: "Malware", detectedBy: ["LocalDB"] };
  } else if (suspiciousList.includes(val)) {
    return { status: "⚠️ Suspicious!", stats: { malicious: 1 }, total_engines: 5, threatType: "Suspicious", detectedBy: ["LocalDB"] };
  } else {
    return { status: "✅ No threat found", stats: { malicious: 0 }, total_engines: 5, threatType: "Safe", detectedBy: ["LocalDB"] };
  }
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
    await axios.post("https://www.virustotal.com/api/v3/urls", `url=${url}`, {
      headers: { "x-apikey": process.env.VT_API_KEY, "Content-Type": "application/x-www-form-urlencoded" },
    });
    const urlId = Buffer.from(url).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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

// 🔹 Scan route
app.post("/api/scan", async (req, res) => {
  const { input } = req.body;
  if (!input) return res.status(400).json({ message: "No input provided" });

  let result = null;

  try {
    if (isIP(input)) {
      const abuseResult = await checkAbuseIPDB(input);
      const score = abuseResult?.abuseConfidenceScore || 0;
      result = {
        input,
        status: getStatus(0, score),
        stats: { abuseConfidenceScore: score },
        total_engines: 1,
        threatType: score > 50 ? "High Risk IP" : score > 0 ? "Suspicious IP" : "Safe IP",
        detectedBy: ["AbuseIPDB"],
      };
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
          detectedBy: Object.keys(vtStats).filter(k => vtStats[k] > 0),
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
          detectedBy: Object.keys(vtStats).filter(k => vtStats[k] > 0),
        };
      }
    }

    // Merge local check if API result exists
    const localResult = localThreatCheck(input);
    if (result) {
      result.total_engines += localResult.total_engines;
      result.detectedBy = [...new Set([...result.detectedBy, ...localResult.detectedBy])];
      if (result.status.includes("No threat") && !localResult.status.includes("No threat")) {
        result.status = localResult.status;
        result.threatType = localResult.threatType;
      }
    } else {
      // fallback entirely to local check
      result = localResult;
    }

    await Scan.create(result);
    res.json(result);
  } catch (err) {
    console.error("Scan error:", err.message);
    res.json(localThreatCheck(input));
  }
});

// 🔹 History
app.get("/api/history", async (req, res) => {
  try {
    const scans = await Scan.find().sort({ date: -1 }).limit(5);
    res.json(scans);
  } catch (err) {
    res.status(500).json({ error: "Error fetching history" });
  }
});

app.get("/api/hello", (req, res) => res.json({ message: "Backend is working" }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
