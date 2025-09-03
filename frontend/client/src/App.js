import { useState, useEffect } from "react";
import axios from "axios";
import {
  ShieldCheck,
  ShieldAlert,
  Shield,
  ShieldX,
  History,
  Globe,
  KeyRound,
  Loader2,
} from "lucide-react";

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
  const [history, setHistory] = useState(() => {
    const saved = localStorage.getItem("scanHistory");
    return saved ? JSON.parse(saved) : [];
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showDetected, setShowDetected] = useState(false);

  useEffect(() => {
    localStorage.setItem("scanHistory", JSON.stringify(history));
  }, [history]);

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

      setHistory((prev) => {
        const newEntry = {
          input: data.input,
          status: data.status,
          type: inputType(data.input),
          time: new Date().toLocaleString(),
          result: data,
        };
        const filtered = prev.filter(
          (h) => h.input?.toLowerCase() !== scannedInput.toLowerCase()
        );
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

  const getStatusStyle = (status) => {
    if (status?.includes("High Threat"))
      return "text-red-600 font-bold";
    if (status?.includes("Suspicious"))
      return "text-yellow-600 font-bold";
    if (status?.includes("No threat"))
      return "text-green-600 font-bold";
    return "text-gray-600 font-bold";
  };

  const getStatusIcon = (status) => {
    if (status?.includes("High Threat"))
      return <ShieldX className="text-red-500 w-6 h-6" />;
    if (status?.includes("Suspicious"))
      return <Shield className="text-yellow-500 w-6 h-6" />;
    if (status?.includes("No threat"))
      return <ShieldCheck className="text-green-500 w-6 h-6" />;
    return <ShieldAlert className="text-red-400 w-6 h-6" />;
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
            placeholder="Enter URL, IP, or file hash..."
            className="flex-1 p-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-pink-400"
          />
          <button
            onClick={handleScan}
            disabled={loading || !validateInput(input.trim())}
            className="px-4 py-2 bg-pink-600 text-white rounded-lg hover:bg-pink-500 disabled:bg-gray-400"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin inline-block mr-2" />
                Scanning...
              </>
            ) : (
              "Scan"
            )}
          </button>
        </div>
        {error && <p className="text-red-600 mt-2">{error}</p>}
      </div>

      {/* Result */}
      {result && (
        <div className="w-full max-w-2xl bg-white shadow-lg rounded-xl p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 text-center">Scan Result</h2>
          <table className="w-full text-sm border border-gray-300 rounded-lg overflow-hidden">
            <tbody>
              <tr className="border-b">
                <td className="p-3 font-semibold w-1/3">Input</td>
                <td className="p-3">{result.input}</td>
              </tr>
              <tr className="border-b">
                <td className="p-3 font-semibold">Status</td>
                <td className={`p-3 flex items-center gap-2 ${getStatusStyle(result.status)}`}>
                  {getStatusIcon(result.status)} {result.status}
                </td>
              </tr>
              <tr className="border-b">
                <td className="p-3 font-semibold">Engines</td>
                <td className="p-3">
                  {result.total_engines ?? 0} | Malicious:{" "}
                  {result.stats?.malicious ?? 0}
                </td>
              </tr>
              <tr className="border-b">
                <td className="p-3 font-semibold">Threat Type</td>
                <td className="p-3">{result.threatType ?? "Unknown"}</td>
              </tr>
              <tr>
                <td className="p-3 font-semibold">Detected By</td>
                <td className="p-3">
                  {result.detectedBy?.length > 0 ? (
                    <ul className="list-disc ml-5">
                      {result.detectedBy.map((engine, i) => (
                        <li key={i}>{engine}</li>
                      ))}
                    </ul>
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
                  onClick={() => {
                    if (h.result) setResult(h.result);
                    setShowDetected(false);
                  }}
                  className="border-t hover:bg-pink-50 cursor-pointer"
                >
                  <td className="p-2">{h.input}</td>
                  <td className="p-2 capitalize">{h.type}</td>
                  <td className={`p-2 ${getStatusStyle(h.status)}`}>
                    {h.status}
                  </td>
                  <td className="p-2 text-xs">{h.time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
