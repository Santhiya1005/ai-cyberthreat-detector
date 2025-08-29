const express = require("express");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

app.get("/api/hello", (req, res) => {
  res.json({ message: "Backend is working fine 🚀" });
});

app.post("/api/scan", (req, res) => {
  const { input } = req.body;

  if (!input) {
    return res.status(400).json({ message: "No input provided" });
  }

  const isThreat = input.toLowerCase().includes("malware");
  res.json({
    input,
    result: isThreat ? "⚠️ Threat detected!" : "✅ No threat found",
  });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
