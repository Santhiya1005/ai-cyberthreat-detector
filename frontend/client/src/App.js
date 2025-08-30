import React, { useState, useEffect } from "react";

function App() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState("");
  const [history, setHistory] = useState([]);

  // 🔹 Fetch last 5 scans and auto-refresh every 15 seconds
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await fetch("/api/history");
        const data = await res.json();
        setHistory(Array.isArray(data) ? data : []);
      } catch (err) {
        console.error("Error fetching history:", err);
      }
    };

    fetchHistory(); // initial fetch
    const interval = setInterval(fetchHistory, 15000); // refresh every 15 sec
    return () => clearInterval(interval); // cleanup on unmount
  }, []);

  const handleScan = async () => {
    if (!input) return;
    setResult("Scanning...");

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input }),
      });

      const data = await res.json();

      if (data.error) {
        setResult("Error: " + data.error);
        return;
      }

      setResult(`${data.input}: ${data.status}`);

      const scanItem = {
        input: data.input,
        status: data.status,
        stats: data.stats,
        total_engines:
          data.total_engines || Object.values(data.stats || {}).reduce((a, b) => a + b, 0),
      };

      // Update history (keep last 5)
      setHistory((prev = []) => [scanItem, ...prev].slice(0, 5));
      setInput("");
    } catch (err) {
      setResult("Error: " + err.message);
    }
  };

  // 🔹 Color-code status
  const getStatusColor = (stats) => {
    if (stats?.malicious > 0) return "red";
    if (stats?.suspicious > 0) return "orange";
    return "green";
  };

  return (
    <div style={{ textAlign: "center", marginTop: "50px" }}>
      <h1>Cyberthreat Detector</h1>
      <input
        type="text"
        placeholder="Enter URL or file hash"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        style={{ width: "300px", padding: "10px", margin: "10px" }}
      />
      <br />
      <button onClick={handleScan} style={{ padding: "10px 20px" }}>
        Scan
      </button>

      <h2>{result}</h2>

      {history.length > 0 && (
        <div style={{ marginTop: "30px" }}>
          <h3>Scan History (Last 5)</h3>
          <ul style={{ listStyle: "none", padding: 0 }}>
            {history.map((item, index) => (
              <li key={index} style={{ marginBottom: "15px" }}>
                <b>{item.input}:</b>{" "}
                <span style={{ color: getStatusColor(item.stats) }}>{item.status}</span>{" "}
                <span style={{ color: "gray" }}>
                  (Engines checked: {item.total_engines})
                </span>
                <br />
                <span style={{ fontSize: "0.9em", color: "gray" }}>
                  Harmless: {item.stats?.harmless || 0} |{" "}
                  Malicious: {item.stats?.malicious || 0} |{" "}
                  Suspicious: {item.stats?.suspicious || 0} |{" "}
                  Undetected: {item.stats?.undetected || 0}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;
