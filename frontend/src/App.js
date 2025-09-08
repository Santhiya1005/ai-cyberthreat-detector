import React, { useState, useEffect } from "react";
import axios from "axios";
import "./App.css"; // cyber styles

function App() {
  const [input, setInput] = useState("");
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loginLoading, setLoginLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedScan, setSelectedScan] = useState(null);

  useEffect(() => {
    if (token) fetchHistory();
  }, [token]);

  const mapStatus = (aiPrediction, originalStatus) => {
    if (!aiPrediction || aiPrediction.toLowerCase() === "unknown")
      return originalStatus || "✅ No Threat";

    const lower = aiPrediction.toLowerCase();
    if (lower.includes("malware")) return "🚨 High Threat!";
    if (lower.includes("phish") || lower.includes("suspicious"))
      return "⚠️ Suspicious";
    if (lower.includes("benign") || lower.includes("safe"))
      return "✅ No Threat";

    return originalStatus || "Unknown";
  };

  const handleLogin = async () => {
    setLoginLoading(true);
    setError("");
    try {
      const res = await axios.post("http://localhost:4000/api/login", {
        username: "admin",
        password: "password123",
      });
      const { token } = res.data;
      setToken(token);
      localStorage.setItem("token", token);
      fetchHistory();
    } catch (err) {
      setError(err.response?.data?.message || "Login failed.");
    } finally {
      setLoginLoading(false);
    }
  };

  const fetchHistory = async () => {
    if (!token) return;
    try {
      const res = await axios.get("http://localhost:4000/api/history", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const mappedHistory = res.data.map((item) => ({
        ...item,
        status: mapStatus(item.aiPrediction, item.status),
      }));
      setHistory(mappedHistory);
    } catch (err) {
      console.error(err);
    }
  };

  const handleScan = async () => {
    const trimmed = input.trim();
    if (!trimmed) return;
    if (!token) return setError("Please login first.");
    setLoading(true);
    setError("");
    try {
      const res = await axios.post(
        "http://localhost:4000/api/scan",
        { input: trimmed },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const item = res.data;
      item.status = mapStatus(item.aiPrediction, item.status);
      setHistory((prev) => [item, ...prev]);
      setSelectedScan(item);
      setInput("");
    } catch (err) {
      setError(err.response?.data?.message || "Scan failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    try {
      await axios.delete(`http://localhost:4000/api/history/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setHistory((prev) => prev.filter((i) => i._id !== id));
      if (selectedScan?._id === id) setSelectedScan(null);
    } catch (err) {
      console.error(err);
    }
  };

  const handleClearHistory = async () => {
    try {
      await axios.delete("http://localhost:4000/api/history", {
        headers: { Authorization: `Bearer ${token}` },
      });
      setHistory([]);
      setSelectedScan(null);
    } catch (err) {
      console.error(err);
    }
  };

  const handleLogout = () => {
    setToken("");
    localStorage.removeItem("token");
    setHistory([]);
    setSelectedScan(null);
    setInput("");
    setError("");
  };

  return (
    <div className="video-background">
      <video autoPlay loop muted className="video-bg">
        <source src="/cyber-bg.mp4" type="video/mp4" />
        Your browser does not support the video tag.
      </video>

      <div className="overlay-content">
        <h1 className="cyber-title">🚨 CyberThreat Detector</h1>

        {!token ? (
          <div>
            <button
              className="btn-cyber"
              onClick={handleLogin}
              disabled={loginLoading}
            >
              {loginLoading ? "Logging in..." : "Login"}
            </button>
            {error && <p className="text-danger mt-2">{error}</p>}
          </div>
        ) : (
          <div>
            {/* 🔍 Input + Scan Button */}
            <div className="input-button-container">
              <input
                type="text"
                className="cyber-input"
                placeholder="Enter URL, IP, or file hash"
                value={input}
                onChange={(e) => setInput(e.target.value)}
              />
              <button
                className="btn-cyber"
                onClick={handleScan}
                disabled={loading}
              >
                {loading ? "Scanning..." : "Scan"}
              </button>
            </div>

            {/* 🚪 Logout + Clear History Buttons */}
            <div className="btn-row">
              <button className="btn-cyber" onClick={handleLogout}>
                Logout
              </button>
              <button className="btn-cyber" onClick={handleClearHistory}>
                Clear History
              </button>
            </div>

            {error && <p className="text-danger">{error}</p>}

            {/* 📝 Selected Scan */}
            {selectedScan && (
              <div className="cyber-card">
                <h5>Scan Result (Selected Row):</h5>
                <pre>{JSON.stringify(selectedScan, null, 2)}</pre>
              </div>
            )}

            <h3 className="cyber-subtitle">Recent Scans</h3>
            <table className="table-cyber">
              <thead>
                <tr>
                  <th>Input</th>
                  <th>AI Prediction</th>
                  <th>Status</th>
                  <th>Date/Time</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {history.length === 0 && (
                  <tr>
                    <td colSpan={5} className="text-center">
                      No scans yet.
                    </td>
                  </tr>
                )}
                {history.map((item) => (
                  <tr
                    key={item._id}
                    style={{
                      cursor: "pointer",
                      backgroundColor:
                        selectedScan?._id === item._id
                          ? "rgba(140, 17, 234, 0.1)"
                          : "transparent",
                      color: "#fff",
                    }}
                    onClick={() => setSelectedScan(item)}
                  >
                    <td>{item.input}</td>
                    <td>{item.aiPrediction || "N/A"}</td>
                    <td>{item.status}</td>
                    <td>{new Date(item.date).toLocaleString()}</td>
                    <td>
                      <button
                        className="btn-cyber"
                        style={{
                          padding: "6px 12px",
                          minWidth: "auto",
                          fontSize: "0.85rem",
                        }}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDelete(item._id);
                        }}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
