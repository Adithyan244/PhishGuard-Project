import React, { useState } from 'react';
import { Shield, Activity, AlertTriangle, CheckCircle, Search, Loader2 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const mockChartData = [
  { name: 'Mon', malicious: 4, benign: 12 },
  { name: 'Tue', malicious: 7, benign: 15 },
  { name: 'Wed', malicious: 2, benign: 18 },
  { name: 'Thu', malicious: 9, benign: 10 },
  { name: 'Fri', malicious: 3, benign: 22 },
];

export default function App() {
  // --- REACT STATE: This is the memory of our app ---
  const [targetUrl, setTargetUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  // --- THE BRIDGE: This talks to your Python API ---
  const handleScan = async (e) => {
    e.preventDefault();
    if (!targetUrl) return;

    setIsScanning(true);
    setScanResult(null);

    try {
      // We shoot the URL over to Python running on port 8000
      const response = await fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: targetUrl }), // Must match your Pydantic BaseModel in Python!
      });

      if (!response.ok) throw new Error("API Connection Failed");

      const data = await response.json();
      setScanResult(data); // Save the Python AI's answer into React's memory
      
    } catch (error) {
      console.error("Scan Error:", error);
      setScanResult({ error: "Failed to connect to Python backend. Is uvicorn running?" });
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-8">
      {/* HEADER & SEARCH BAR */}
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-8 border-b border-slate-700 pb-6">
        <div className="flex items-center gap-3">
          <Shield className="w-10 h-10 text-blue-500" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">PhishGuard AI</h1>
            <p className="text-slate-400">Live Threat Intelligence Dashboard</p>
          </div>
        </div>

        {/* The Input Form */}
        <form onSubmit={handleScan} className="flex w-full md:w-auto gap-2">
          <input 
            type="url" 
            placeholder="Enter URL to scan..." 
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="flex-1 md:w-80 bg-slate-800 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-blue-500 transition-colors"
            required
          />
          <button 
            type="submit" 
            disabled={isScanning}
            className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-semibold flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            {isScanning ? <Loader2 className="w-5 h-5 animate-spin" /> : <Search className="w-5 h-5" />}
            Scan
          </button>
        </form>
      </header>

      {/* TOP STATS CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 flex items-center gap-4">
          <Activity className="w-12 h-12 text-blue-400" />
          <div>
            <p className="text-slate-400 text-sm font-semibold uppercase">Total Scans</p>
            <p className="text-3xl font-bold">1,024</p>
          </div>
        </div>
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 flex items-center gap-4">
          <AlertTriangle className="w-12 h-12 text-rose-500" />
          <div>
            <p className="text-slate-400 text-sm font-semibold uppercase">Threats Blocked</p>
            <p className="text-3xl font-bold">89</p>
          </div>
        </div>
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 flex items-center gap-4">
          <CheckCircle className="w-12 h-12 text-emerald-500" />
          <div>
            <p className="text-slate-400 text-sm font-semibold uppercase">Backend Bridge</p>
            <p className="text-xl font-bold text-emerald-500">Connected</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* CHART SECTION */}
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h2 className="text-xl font-semibold mb-6">Threat Distribution (7 Days)</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={mockChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" />
                <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px', color: '#fff' }} />
                <Bar dataKey="malicious" fill="#f43f5e" name="Malicious" />
                <Bar dataKey="benign" fill="#10b981" name="Safe" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* LIVE SCAN RESULTS SECTION */}
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h2 className="text-xl font-semibold mb-6">Active Telemetry</h2>
          
          {!scanResult && !isScanning && (
            <p className="text-slate-400 text-center mt-10">Enter a URL above to initialize the AI analysis pipeline.</p>
          )}

          {isScanning && (
             <div className="animate-pulse space-y-4">
               <div className="h-4 bg-slate-700 rounded w-3/4"></div>
               <div className="h-4 bg-slate-700 rounded w-1/2"></div>
               <div className="h-4 bg-slate-700 rounded w-5/6"></div>
             </div>
          )}

          {scanResult && !scanResult.error && (
            <div className={`p-4 rounded-lg border ${scanResult.status === 'MALICIOUS' ? 'bg-rose-950/30 border-rose-500/50' : 'bg-emerald-950/30 border-emerald-500/50'}`}>
              <div className="flex justify-between items-center mb-4">
                <h3 className="font-bold text-lg">Verdict: <span className={scanResult.status === 'MALICIOUS' ? 'text-rose-500' : 'text-emerald-500'}>{scanResult.status}</span></h3>
                <span className="text-2xl font-black">{Number(scanResult.risk_score_percentage).toFixed(2)}% Risk</span>
              </div>
              
              <div className="bg-slate-900 rounded p-3 font-mono text-sm break-all mb-4 text-slate-300">
                Target: {scanResult.target_url}
              </div>

              {scanResult.forensics_report && (
                <div>
                  <p className="text-sm text-slate-400 font-semibold mb-2">Forensics Data:</p>
                  <pre className="bg-slate-900 p-3 rounded text-xs text-slate-300 overflow-x-auto">
                    {JSON.stringify(scanResult.forensics_report, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}

          {scanResult?.error && (
             <div className="p-4 bg-rose-950/30 border border-rose-500/50 rounded-lg text-rose-500">
                {scanResult.error}
             </div>
          )}
        </div>
      </div>
    </div>
  );
}