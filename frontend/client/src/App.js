import { useState, useEffect } from "react";
import axios from "axios";
import { ShieldCheck, ShieldAlert, Shield, ShieldX, History, Globe, KeyRound, Loader2 } from "lucide-react";

// Validation regex
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
  const [showDetected, setShowDetected] = useState(false);

  // Scan function
  const handleScan = async (customInput = null) => {
    const scannedInput = (customInput || input).trim();
    if (!validateInput(scannedInput)) {
      setError("❌ Please enter a valid URL, IP, or file hash");
      return;
    }

    setError("");
    setLoading(true);

    try {
      // Call backend
      const res = await axios.post("http://localhost:4000/api/scan", { input: scannedInput });
      setResult(res.data);

      // Update history
      setHistory((prev) => {
        const newEntry = { input: scannedInput, status: res.data.status, result: res.data };
        const filtered = prev.filter((h) => h.input?.toLowerCase() !== scannedInput.toLowerCase());
        return [newEntry, ...filtered].slice(0, 5);
      });
    } catch (err) {
      console.error("Scan error:", err);
      setError("❌ Scan failed. Try again.");
    } finally {
      setLoading(false);
      setInput("");
      setShowDetected(false);
    }
  };

  // Fetch recent history from backend
  const fetchHistory = async () => {
    try {
      const res = await axios.get("http://localhost:4000/api/history");
      const mapped = res.data.map((scan) => ({ input: scan.input, status: scan.status, result: scan }));
      setHistory(mapped);
    } catch {
      setHistory([]);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const getStatusStyle = (status) => {
    if (status?.includes("High Threat")) return "bg-red-600/30 text-red-400 border border-red-600/50";
    if (status?.includes("Suspicious")) return "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30";
    if (status?.includes("No threat")) return "bg-green-500/20 text-green-400 border border-green-500/30";
    return "bg-gray-500/20 text-gray-300 border border-gray-500/30";
  };

  const getStatusIcon = (status) => {
    if (status?.includes("High Threat")) return <ShieldX className="text-red-500 w-8 h-8 animate-pulse" />;
    if (status?.includes("Suspicious")) return <Shield className="text-yellow-400 w-8 h-8 animate-pulse" />;
    if (status?.includes("No threat")) return <ShieldCheck className="text-green-400 w-8 h-8 animate-pulse" />;
    return <ShieldAlert className="text-red-400 w-8 h-8 animate-pulse" />;
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-start bg-gradient-to-br from-gray-900 via-black to-gray-950 text-white p-6">
      <h1 className="text-5xl font-bold text-center text-blue-400 mb-8">⚡ CyberThreat Detector</h1>

      {/* Input Card */}
      <div className="w-full max-w-md bg-gray-900/80 shadow-2xl p-6 rounded-3xl flex flex-col gap-4">
        <div className="relative">
          <input
            type="text"
            value={input}
            disabled={loading}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Enter URL, IP, or file hash..."
            className="w-full p-3 pl-10 rounded-xl bg-gray-800 text-white outline-none border border-gray-700 focus:border-blue-500 transition"
          />
          {input && (
            <span className="absolute left-3 top-3 text-gray-400">
              {inputType(input) === "url" ? <Globe className="w-5 h-5" /> : inputType(input) === "hash" ? <KeyRound className="w-5 h-5" /> : null}
            </span>
          )}
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
        <button
          onClick={() => handleScan()}
          disabled={loading || !validateInput(input.trim())}
          className={`w-full py-3 rounded-xl font-semibold transition flex justify-center items-center gap-2 ${loading || !validateInput(input.trim()) ? "bg-gray-600 cursor-not-allowed" : "bg-blue-600 hover:bg-blue-500"}`}
        >
          {loading ? <><Loader2 className="w-5 h-5 animate-spin" /> Scanning...</> : "Scan"}
        </button>
      </div>

      {/* Result Card */}
      {result && (
        <div className="w-full max-w-md bg-gray-900/80 shadow-2xl p-6 rounded-3xl mt-6 text-center">
          <h2 className="text-2xl font-semibold mb-3">Scan Result</h2>
          <div className="flex flex-col items-center gap-3">
            {getStatusIcon(result.status)}
            <span className={`px-4 py-2 rounded-lg text-lg font-semibold ${getStatusStyle(result.status)}`}>
              {result.status}
            </span>
            <p className="mt-1 text-gray-400 text-sm">
              Engines: {result.total_engines ?? 0} | Malicious: {result.stats?.malicious ?? 0}
            </p>
            <p className="text-gray-400 text-sm">Threat Type: {result.threatType ?? "Unknown"}</p>
            {result.detectedBy?.length > 0 && (
              <div className="text-gray-300 text-sm mt-1 w-full">
                <strong>Detected By:</strong>
                <button onClick={() => setShowDetected(!showDetected)} className="ml-2 text-blue-400 text-xs underline">
                  {showDetected ? "Hide" : "Show"}
                </button>
                {showDetected && (
                  <ul className="list-disc ml-5 text-left mt-2 bg-gray-800/40 p-2 rounded-lg max-h-40 overflow-auto">
                    {result.detectedBy
                      .filter((engine) => engine !== "harmless" && engine !== "undetected")
                      .map((engine, i) => (<li key={i}>{engine}</li>))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* History Card */}
      <div className="w-full max-w-md bg-gray-900/80 shadow-2xl p-6 rounded-3xl mt-6">
        <h2 className="flex items-center justify-center gap-2 text-xl font-semibold mb-4">
          <History className="w-5 h-5 text-blue-400" /> Recent Scans
        </h2>
        {history.length === 0 ? (
          <p className="text-gray-500 text-center">No history found</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {history.map((h, i) => (
              <li key={i} onClick={() => { if (h.result) setResult(h.result); setShowDetected(false); }} className="flex items-center justify-between p-3 bg-gray-800/60 rounded-xl hover:bg-gray-700/70 transition cursor-pointer">
                <span className="truncate w-2/3">{h.input}</span>
                <span className={`px-2 py-1 rounded-lg text-sm font-semibold ${getStatusStyle(h.status)}`}>
                  {h.status}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
