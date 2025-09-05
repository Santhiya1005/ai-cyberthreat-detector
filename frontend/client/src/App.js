import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  ShieldCheck,
  ShieldAlert,
  Shield,
  ShieldX,
  History,
} from "lucide-react";
import "bootstrap/dist/css/bootstrap.min.css";

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

const getAIPrediction = (status) => {
  if (!status) return "N/A";
  const s = status.toLowerCase();
  if (s.includes("high") || s.includes("malicious") || s.includes("danger"))
    return "Malware";
  if (s.includes("suspicious")) return "Phishing";
  return "Benign";
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

  const getStatusClass = (status) => {
    if (!status) return "text-secondary fw-bold";
    const s = status.toLowerCase();
    if (s.includes("malicious") || s.includes("high") || s.includes("danger"))
      return "text-danger fw-bold";
    if (s.includes("suspicious")) return "text-warning fw-bold";
    if (s.includes("benign") || s.includes("no")) return "text-success fw-bold";
    return "text-secondary fw-bold";
  };

  const getStatusIcon = (status) => {
    if (!status) return <ShieldAlert className="me-2" />;
    const s = status.toLowerCase();
    if (s.includes("malicious") || s.includes("high") || s.includes("danger"))
      return <ShieldX className="text-danger me-2" />;
    if (s.includes("suspicious"))
      return <Shield className="text-warning me-2" />;
    if (s.includes("benign") || s.includes("no"))
      return <ShieldCheck className="text-success me-2" />;
    return <ShieldAlert className="me-2" />;
  };

  const getBadgeClass = (prediction) => {
    const p = (prediction ?? "").toLowerCase();
    if (p === "malware") return "bg-danger";
    if (p === "phishing") return "bg-warning text-dark";
    if (p === "benign") return "bg-success";
    return "bg-secondary";
  };

  return (
    <div
      className="container-fluid min-vh-100 py-4"
    >
        {/* App Header */}
<div className="text-center mb-5">
  <h1 className="fw-bold text-danger py-3">
    ⚡ CyberThreat Detector
  </h1>
</div>




      {/* Input */}
      <div className="card mb-4 shadow-sm">
        <div className="card-body">
          <div className="input-group">
            <input
              type="text"
              value={input}
              disabled={loading}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              className="form-control"
              placeholder="Enter URL, IP, or file hash..."
            />
            <button
              className="btn btn-danger"
              disabled={loading || !validateInput(input.trim())}
              onClick={handleScan}
            >
              {loading ? (
                <div
                  className="spinner-border spinner-border-sm me-2"
                  role="status"
                >
                  <span className="visually-hidden">Loading...</span>
                </div>
              ) : null}
              {loading ? "Scanning..." : "Scan"}
            </button>
          </div>
          {error && <div className="text-danger mt-2">{error}</div>}
        </div>
      </div>

      {/* Scan Result */}
      {result && (
        <div className="card mb-4 shadow-sm">
          <div className="card-body">
            <h5 className="card-title text-center mb-4 fw-bold">Scan Result</h5>
            <div className="table-responsive">
              <table className="table table-bordered table-hover align-middle">
                <tbody>
                  <tr>
                    <td className="fw-bold">Input</td>
                    <td>{result.input}</td>
                  </tr>
                  <tr>
                    <td className="fw-bold">Status</td>
                    <td
                      className={`d-flex align-items-center ${getStatusClass(
                        result.status
                      )}`}
                    >
                      {getStatusIcon(result.status)}
                      {result.status ?? "Unknown"}
                    </td>
                  </tr>
                  <tr>
                    <td className="fw-bold">AI Prediction</td>
                    <td>
                      <span
                        className={`badge ${getBadgeClass(
                          result.aiPrediction ?? getAIPrediction(result.status)
                        )}`}
                      >
                        🧠{" "}
                        {result.aiPrediction ?? getAIPrediction(result.status)}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td className="fw-bold">Detected By</td>
                    <td>
                      {result.detectedBy?.length > 0 ? (
                        <ul className="mb-0 ps-3">
                          {[...new Set(result.detectedBy)]
                            .sort()
                            .map((engine, i) => (
                              <li key={i}>{engine}</li>
                            ))}
                        </ul>
                      ) : (
                        "LocalDB"
                      )}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* History */}
      <div className="card shadow-sm">
        <div className="card-body">
          <h5 className="card-title mb-3 fw-bold">
            <History className="me-2 text-danger" /> Recent Scans
          </h5>
          {history.length === 0 ? (
            <p className="text-secondary">No history found</p>
          ) : (
           <div className="table-responsive">
  <table className="table table-bordered table-hover align-middle">
    <thead className="table-light">
      <tr>
        <th>Input</th>
        <th>Type</th>
        <th>Status</th>
        <th>AI Prediction</th>
        <th>Detected By</th>
        <th>Time</th>
      </tr>
    </thead>
    <tbody>
      {history.map((h, i) => (
        <tr
          key={i}
          onClick={() => setResult(h)}
          className={`${i % 2 === 0 ? "bg-light" : ""} ${
            result?.input === h.input ? "table-active" : ""
          }`}
          style={{ cursor: "pointer" }}
        >
          <td>{h.input}</td>
          <td className="text-capitalize">{inputType(h.input)}</td>
          <td className={`d-flex align-items-center ${getStatusClass(h.status)}`}>
            {getStatusIcon(h.status)}
            {h.status ?? "Unknown"}
          </td>
          <td>
            <span
              className={`badge ${getBadgeClass(h.aiPrediction ?? getAIPrediction(h.status))}`}
            >
              🧠 {h.aiPrediction ?? getAIPrediction(h.status)}
            </span>
          </td>
          <td>
            {h.detectedBy?.length > 0 ? (
              <>
                <button
                  className="btn btn-sm btn-outline-primary"
                  type="button"
                  data-bs-toggle="collapse"
                  data-bs-target={`#detected-${i}`}
                  aria-expanded="false"
                  aria-controls={`detected-${i}`}
                >
                  View ({h.detectedBy.length})
                </button>
                <div className="collapse mt-2" id={`detected-${i}`}>
                  <ul className="mb-0 ps-3">
                    {h.detectedBy.map((engine, idx) => (
                      <li key={idx}>{engine}</li>
                    ))}
                  </ul>
                </div>
              </>
            ) : (
              "LocalDB"
            )}
          </td>
          <td className="text-nowrap">{new Date(h.date).toLocaleString()}</td>
        </tr>
      ))}
    </tbody>
  </table>
</div>

          )}
        </div>
      </div>
    </div>
  );
}
