require("dotenv").config();
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const mongoose = require("mongoose");
const net = require("net");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());
app.use(cors({ origin: "*" }));

// -------------------- Env check --------------------
const requiredEnvs = [
  "VT_API_KEY",
  "ABUSEIPDB_KEY",
  "MONGO_URL",
  "ACCESS_TOKEN_SECRET",
  "ACCESS_TOKEN_EXPIRE_MINUTES",
  "AI_URL",
];
for (const k of requiredEnvs) {
  if (!process.env[k]) {
    console.error(`❌ Missing required environment variable: ${k}`);
    process.exit(1);
  }
}

// -------------------- MongoDB --------------------
mongoose
  .connect(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB error:", err.message);
    process.exit(1);
  });

// -------------------- JWT Auth --------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// -------------------- Dummy user --------------------
const dummyUser = {
  id: 1,
  username: "admin",
  password: bcrypt.hashSync("password123", 10),
};

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ message: "username & password required" });
  if (username !== dummyUser.username)
    return res.status(400).json({ message: "Invalid credentials" });
  const validPass = await bcrypt.compare(password, dummyUser.password);
  if (!validPass) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { id: dummyUser.id, username: dummyUser.username },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: `${process.env.ACCESS_TOKEN_EXPIRE_MINUTES}m` }
  );
  res.json({ token });
});

// -------------------- Scan Schema --------------------
const scanSchema = new mongoose.Schema({
  input: { type: String, required: true },
  status: String,
  stats: Object,
  total_engines: Number,
  threatType: String,
  aiPrediction: String,
  detectedBy: [String],
  date: { type: Date, default: Date.now },
});
const Scan = mongoose.model("Scan", scanSchema);

// -------------------- Local dataset --------------------
let maliciousData = [];
try {
  maliciousData = require(path.join(__dirname, "malicious.json"));
} catch {
  console.warn("⚠️ malicious.json not found, local DB disabled");
}

// -------------------- Helpers --------------------
function isIP(input) {
  return net.isIP(input) !== 0;
}
function isHash(input) {
  return /^[a-fA-F0-9]{32,64}$/.test(input);
}
function isURL(input) {
  return /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/.*)?$/i.test(input);
}
function localThreatCheck(input) {
  const val = input.trim().toLowerCase();
  const found = maliciousData.find((item) => String(item.value).toLowerCase() === val);
  if (found) {
    const type = found.type || "unknown";
    return {
      input,
      status: "🚨 High Threat!",
      stats: { malicious: 5 },
      total_engines: 1,
      threatType: type,
      detectedBy: ["LocalDB"],
    };
  }
  return {
    input,
    status: "✅ No Threat",
    stats: { malicious: 0 },
    total_engines: 0,
    threatType: "Safe",
    detectedBy: ["LocalDB"],
  };
}

// -------------------- Third-party APIs --------------------
const VT_API = axios.create({
  baseURL: "https://www.virustotal.com/api/v3",
  timeout: 15000,
  headers: { "x-apikey": process.env.VT_API_KEY },
});
const ABUSE_API = axios.create({
  baseURL: "https://api.abuseipdb.com/api/v2",
  timeout: 10000,
  headers: { Key: process.env.ABUSEIPDB_KEY, Accept: "application/json" },
});

async function checkIP(ip) {
  try {
    const response = await ABUSE_API.get("/check", {
      params: { ipAddress: ip, maxAgeInDays: 90 },
    });
    const score = Number(response.data?.data?.abuseConfidenceScore || 0);
    if (score >= 50)
      return { status: "🚨 High Threat!", detectedBy: ["AbuseIPDB"], threatType: "High Risk IP", score };
    if (score > 0)
      return { status: "⚠️ Suspicious", detectedBy: ["AbuseIPDB"], threatType: "Suspicious IP", score };
    return { status: "✅ No Threat", detectedBy: ["AbuseIPDB"], threatType: "Safe", score };
  } catch (err) {
    console.warn("AbuseIPDB error:", err.message || err);
    return { status: "Unknown", detectedBy: ["AbuseIPDB"], threatType: "Unknown" };
  }
}

async function checkVirusTotalURL(inputUrl) {
  try {
    const urlToPost = inputUrl.startsWith("http") ? inputUrl : `http://${inputUrl}`;
    const postRes = await VT_API.post("/urls", `url=${encodeURIComponent(urlToPost)}`, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    const analysisId = postRes?.data?.data?.id;
    if (!analysisId) return { status: "Unknown", detectedBy: ["VirusTotal"], threatType: "Unknown" };

    const getRes = await VT_API.get(`/analyses/${analysisId}`);
    const stats = getRes?.data?.data?.attributes?.stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0) || 0;

    if (malicious > 0) return { status: "🚨 High Threat!", detectedBy: ["VirusTotal"], threatType: "Malware", stats, total_engines: total };
    if (suspicious > 0) return { status: "⚠️ Suspicious", detectedBy: ["VirusTotal"], threatType: "Phishing", stats, total_engines: total };
    return { status: "✅ No Threat", detectedBy: ["VirusTotal"], threatType: "Safe", stats, total_engines: total };
  } catch (err) {
    console.warn("VirusTotal URL error:", err.message || err);
    return { status: "Unknown", detectedBy: ["VirusTotal"], threatType: "Unknown" };
  }
}

async function checkVirusTotalHash(hash) {
  try {
    const getRes = await VT_API.get(`/files/${hash}`);
    const stats = getRes?.data?.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0) || 0;

    if (malicious > 0) return { status: "🚨 High Threat!", detectedBy: ["VirusTotal"], threatType: "Malware", stats, total_engines: total };
    if (suspicious > 0) return { status: "⚠️ Suspicious", detectedBy: ["VirusTotal"], threatType: "Suspicious", stats, total_engines: total };
    return { status: "✅ No Threat", detectedBy: ["VirusTotal"], threatType: "Safe", stats, total_engines: total };
  } catch (err) {
    console.warn("VirusTotal hash error:", err.message || err);
    return { status: "Unknown", detectedBy: ["VirusTotal"], threatType: "Unknown" };
  }
}

// -------------------- AI --------------------
async function queryAI(input) {
  try {
    const res = await axios.post(`${process.env.AI_URL.replace(/\/+$/, "")}/predict`, { input }, { timeout: 10000 });
    return res.data?.prediction || "Unknown";
  } catch (err) {
    console.warn("AI predict error:", err.message || err);
    return "Unknown";
  }
}

async function trainAI(input, label) {
  try {
    await axios.post(`${process.env.AI_URL.replace(/\/+$/, "")}/train`, { input, label }, { timeout: 8000 }).catch(() => {});
  } catch {}
}

// -------------------- Scan --------------------
app.post("/api/scan", authenticateToken, async (req, res) => {
  const { input } = req.body || {};
  if (!input || typeof input !== "string") return res.status(400).json({ message: "No input" });

  const trimmed = input.trim();
  const local = localThreatCheck(trimmed);

  let result = {
    input: trimmed,
    status: local.status,
    stats: local.stats || null,
    total_engines: local.total_engines || 0,
    threatType: local.threatType,
    detectedBy: Array.from(new Set(local.detectedBy || [])),
    aiPrediction: null,
  };

  try {
    const aiPromise = queryAI(trimmed);
    let thirdParty = { status: "Unknown", detectedBy: [], threatType: "Unknown" };

    if (isIP(trimmed)) thirdParty = await checkIP(trimmed);
    else if (isURL(trimmed)) thirdParty = await checkVirusTotalURL(trimmed);
    else if (isHash(trimmed)) thirdParty = await checkVirusTotalHash(trimmed);

    if (thirdParty.status !== "Unknown") {
      result.status = thirdParty.status;
      result.threatType = thirdParty.threatType;
      result.stats = thirdParty.stats || result.stats;
      result.total_engines = thirdParty.total_engines || result.total_engines;
      result.detectedBy = Array.from(new Set([...result.detectedBy, ...thirdParty.detectedBy]));
    }

    const aiPred = await aiPromise;
    result.aiPrediction = aiPred;

    if (thirdParty.status === "Unknown" || (isIP(trimmed) && thirdParty.score === 0)) {
      const lower = aiPred.toLowerCase();
      if (lower.includes("malware")) {
        result.status = "🚨 High Threat!";
        result.threatType = "Malware";
      } else if (lower.includes("phish") || lower.includes("suspicious")) {
        result.status = "⚠️ Suspicious";
        result.threatType = "Phishing";
      } else if (lower.includes("benign") || lower.includes("safe")) {
        result.status = "✅ No Threat";
        result.threatType = "Safe";
      } else {
        result.status = "Unknown";
        result.threatType = "Unknown";
      }
      result.detectedBy.push("AI Model");
    } else {
      if (!result.detectedBy.includes("AI Model")) result.detectedBy.push("AI Model");
    }

    result.detectedBy = Array.from(new Set(result.detectedBy)).sort();

    if (result.threatType && result.threatType !== "Safe" && result.threatType !== "Unknown") {
      trainAI(trimmed, result.threatType).catch(() => {});
    }

    const saved = await Scan.create(result);
    res.json(saved);
  } catch (err) {
    console.error("Scan error:", err.message || err);
    try {
      const fallback = await Scan.create({ ...result, status: result.status || "Unknown" });
      return res.status(200).json(fallback);
    } catch {
      return res.status(500).json({ message: "Internal server error" });
    }
  }
});

// -------------------- History --------------------
app.get("/api/history", authenticateToken, async (req, res) => {
  try {
    const history = await Scan.find({}).sort({ date: -1 }).limit(50);
    res.json(history);
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/api/history/:id", authenticateToken, async (req, res) => {
  try {
    await Scan.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch {
    res.status(500).json({ error: "Failed" });
  }
});

app.delete("/api/history", authenticateToken, async (req, res) => {
  try {
    await Scan.deleteMany({});
    res.json({ message: "Cleared" });
  } catch {
    res.status(500).json({ error: "Failed" });
  }
});

// -------------------- Start --------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
