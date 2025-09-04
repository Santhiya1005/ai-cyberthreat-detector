import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  ShieldCheck,
  ShieldAlert,
  Shield,
  ShieldX,
  History,
  Loader2,
} from "lucide-react";

// Regex validators
const urlRegex = /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/.*)?$/i;
const hashRegex = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const ipRegex = /^\d{1,3}(\.\d{1,3}){3}$/;

const validateInput = (value) =>
  urlRegex.test(value) || hashRegex.test(value) || ipRegex.test(value);

const inputType = (value) => {
  if (urlRegex.test(value)) return "url";
  if (hashRegex.test(value)) return "hash";
  if (ipRegex.test(value)) return "ip";
  return "invalid";
};

export default function CyberThreatDetector() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await axios.get("http://127.0.0.1:4000/api/history");
      setHistory(res.data || []);
    } catch (err) {
      console.error("❌ Error fetching history:", err.message);
    }
  };

  const handleScan = async () => {
    const scannedInput = input.trim();
    if (!validateInput(scannedInput)) {
      setError("❌ Please enter a valid URL, IP, or file hash");
      return;
    }

    setError("");
    setLoading(true);

    try {
      const res = await axios.post("http://127.0.0.1:4000/api/scan", {
        input: scannedInput,
      });

      const data = res.data;
      setResult(data);
      await fetchHistory();
      setInput("");
    } catch (err) {
      console.error("Scan error:", err);
      setError("❌ Unable to reach AI engine. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const getStatusStyle = (status) => {
    if (!status) return "text-gray-600 font-bold";
    const s = status.toLowerCase();
    if (s.includes("malicious") || s.includes("high")) return "text-red-600 font-bold";
    if (s.includes("suspicious")) return "text-yellow-600 font-bold";
    if (s.includes("benign") || s.includes("no")) return "text-green-600 font-bold";
    return "text-gray-600 font-bold";
  };

  const getStatusIcon = (status) => {
    if (!status) return <ShieldAlert className="w-6 h-6 text-gray-400" />;
    const s = status.toLowerCase();
    if (s.includes("malicious") || s.includes("high")) return <ShieldX className="w-6 h-6 text-red-500" />;
    if (s.includes("suspicious")) return <Shield className="w-6 h-6 text-yellow-500" />;
    if (s.includes("benign") || s.includes("no")) return <ShieldCheck className="w-6 h-6 text-green-500" />;
    return <ShieldAlert className="w-6 h-6 text-gray-400" />;
  };

  return (
    <div className="min-h-screen w-full bg-pink-100 flex flex-col items-center p-6 text-gray-900">
      <h1 className="text-4xl font-bold text-center text-pink-700 mb-8">
        ⚡ CyberThreat Detector
      </h1>

      {/* Input */}
      <div className="w-full max-w-2xl bg-white shadow-lg rounded-xl p-6 mb-6">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            disabled={loading}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleScan()}
            placeholder="Enter URL, IP, or file hash..."
            className="flex-1 p-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-pink-400"
          />
          <button
            onClick={handleScan}
            disabled={loading || !validateInput(input.trim())}
            className="px-4 py-2 bg-pink-600 text-white rounded-lg hover:bg-pink-500 disabled:bg-gray-400 flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" /> Scanning...
              </>
            ) : (
              "Scan"
            )}
          </button>
        </div>
        {error && <p className="text-red-600 mt-2">{error}</p>}
      </div>

      {/* Scan Result */}
      {result && (
        <div className="w-full max-w-2xl bg-white shadow-lg rounded-xl p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 text-center">Scan Result</h2>
          <table className="w-full text-sm border border-gray-300 rounded-lg overflow-hidden">
            <tbody>
              <tr className="border-b">
                <td className="p-3 font-semibold">Input</td>
                <td className="p-3 break-all">{result.input}</td>
              </tr>
              <tr className="border-b">
                <td className="p-3 font-semibold">Status</td>
                <td className={`p-3 flex items-center gap-2 ${getStatusStyle(result.status)}`}>
                  {getStatusIcon(result.status)} {result.status ?? "Unknown"}
                </td>
              </tr>
              <tr className="border-b">
                <td className="p-3 font-semibold">AI Prediction</td>
                <td className="p-3">
                  <span
                    className={`px-2 py-1 rounded-full text-white font-semibold ${
                      result.aiPrediction?.toLowerCase() === "malware"
                        ? "bg-red-600"
                        : result.aiPrediction?.toLowerCase() === "phishing"
                        ? "bg-yellow-500"
                        : "bg-green-600"
                    }`}
                  >
                    🧠 {result.aiPrediction ?? "Unknown"}
                  </span>
                </td>
              </tr>
              <tr>
                <td className="p-3 font-semibold">Detected By</td>
                <td className="p-3 flex flex-wrap gap-2">
                  {result.detectedBy?.length > 0 ? (
                    [...new Set(result.detectedBy)].map((engine, i) => (
                      <span
                        key={i}
                        className="bg-pink-100 text-pink-700 px-2 py-1 rounded-full text-xs font-semibold"
                        title={`Detected by ${engine}`}
                      >
                        {engine}
                      </span>
                    ))
                  ) : (
                    "None"
                  )}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      )}

      {/* History */}
      <div className="w-full max-w-2xl bg-white shadow-lg rounded-xl p-6">
        <h2 className="flex items-center gap-2 text-lg font-semibold mb-4">
          <History className="w-5 h-5 text-pink-600" /> Recent Scans
        </h2>
        {history.length === 0 ? (
          <p className="text-gray-500">No history found</p>
        ) : (
          <table className="w-full text-sm border border-gray-300 rounded-lg overflow-hidden">
            <thead className="bg-pink-200 text-gray-900">
              <tr>
                <th className="p-2 text-left">Input</th>
                <th className="p-2 text-left">Type</th>
                <th className="p-2 text-left">Status</th>
                <th className="p-2 text-left">Time</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h, i) => (
                <tr
                  key={i}
                  onClick={() => setResult(h)}
                  className="border-t hover:bg-pink-50 cursor-pointer"
                >
                  <td className="p-2 break-all">{h.input}</td>
                  <td className="p-2 capitalize">{inputType(h.input)}</td>
                  <td className={`p-2 ${getStatusStyle(h.status)}`}>
                    {h.status ?? "Unknown"}
                  </td>
                  <td className="p-2 text-xs">
                    {new Date(h.date).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
