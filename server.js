const express = require("express");
const cors = require("cors");
require("dotenv").config();
const axios = require("axios");

const app = express();
app.use(cors());
app.use(express.json());
const mongoose = require("mongoose");

mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));

// 🔹 Schema for scan history
const scanSchema = new mongoose.Schema({
  input: String,
  status: String,
  stats: Object,
  date: { type: Date, default: Date.now }
});

const Scan = mongoose.model("Scan", scanSchema);

app.get("/api/hello", (req, res) => {
  res.json({ message: "Backend is working" });
});

// 🔹 Route to scan URL or File Hash
app.post("/api/scan", async (req, res) => {
  const { input } = req.body;

  if (!input) {
    return res.status(400).json({ message: "No input provided" });
  }

  try {
    let result;

    if (input.startsWith("http")) {
      // Submit URL for scanning
      const response = await axios.post(
        "https://www.virustotal.com/api/v3/urls",
        `url=${input}`,
        {
          headers: {
            "x-apikey": process.env.VT_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded",
          },
        }
      );

      // Encode URL into base64url format
      const urlId = Buffer.from(input)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

      // Fetch results using encoded URL ID
      result = await axios.get(
        `https://www.virustotal.com/api/v3/urls/${urlId}`,
        { headers: { "x-apikey": process.env.VT_API_KEY } }
      );
    } else {
      // Otherwise assume it’s a file hash (MD5/SHA1/SHA256)
      result = await axios.get(
        `https://www.virustotal.com/api/v3/files/${input}`,
        { headers: { "x-apikey": process.env.VT_API_KEY } }
      );
    }

    // 🔹 Extract detection stats
    const stats = result.data.data?.attributes?.last_analysis_stats;
    const malicious = stats?.malicious || 0;

    // 🔹 Send simplified response
    // 🔹 Send detailed scan response
res.json({
  input,
  status: malicious > 0 ? "⚠️ Threat detected!" : "✅ No threat found",
  stats,
  total_engines: Object.values(stats).reduce((a, b) => a + b, 0), // optional total engines checked
});
// 🔹 Save scan to MongoDB
await Scan.create({
  input,
  status: malicious > 0 ? "⚠️ Threat detected!" : "✅ No threat found",
  stats
});


  } catch (error) {
    console.error("VirusTotal error:", error.response?.data || error.message);
    res.status(500).json({ error: "Error scanning input" });
  }
});
// 🔹 Fetch last 5 scans
app.get("/api/history", async (req, res) => {
  try {
    const scans = await Scan.find().sort({ date: -1 }).limit(5);
    res.json(scans);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching history" });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
