import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";

import Home from "./pages/Home";
import Upload from "./pages/Upload";
import AnalysisProgress from "./pages/AnalysisProgress";
import Dashboard from "./pages/Dashboard";
import Secrets from "./pages/Secrets";
import Endpoints from "./pages/Endpoints";
import AIAnalysis from "./pages/AIAnalysis";
import Report from "./pages/Report";
import About from "./pages/About";

export default function App() {
  return (
    <BrowserRouter>
      <div className="theme-light relative min-h-screen overflow-x-hidden text-slate-900">
        <div className="cyber-background" aria-hidden="true">
          <div className="cyber-grid" />
          <div className="cyber-orbits" />
          <div className="cyber-scan" />
          <div className="cyber-nodes">
            <span />
            <span />
            <span />
            <span />
            <span />
            <span />
          </div>
        </div>
        <Sidebar />
        <div className="relative z-10 lg:ml-64">
          <Navbar />
          <main className="min-h-screen p-4 md:p-6">
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/upload" element={<Upload />} />
              <Route path="/progress" element={<AnalysisProgress />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/secrets" element={<Secrets />} />
              <Route path="/endpoints" element={<Endpoints />} />
              <Route path="/ai-analysis" element={<AIAnalysis />} />
              <Route path="/report" element={<Report />} />
              <Route path="/about" element={<About />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}
