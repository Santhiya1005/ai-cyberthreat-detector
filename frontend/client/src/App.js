import React, { useState } from "react";

function App() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState("");
  const [history, setHistory] = useState([]);

  const handleScan = async () => {
    if (!input) return;
    setResult("Scanning...");
    try {
      const res = await fetch("http://localhost:4000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input }),
      });
      const data = await res.json();
      setResult(data.result);

      // Add to history (keep only last 5)
      setHistory((prev) => [data, ...prev].slice(0, 5));
      setInput(""); // clear input
    } catch (err) {
      setResult("Error: " + err.message);
    }
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
              <li key={index}>
                <b>{item.input}:</b> {item.result}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;
