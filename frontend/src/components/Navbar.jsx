import { Link, useLocation } from "react-router-dom";
import { Plus, Server, ShieldCheck } from "lucide-react";

const titles = {
  "/": "Accueil",
  "/upload": "Upload APK",
  "/progress": "Progression",
  "/dashboard": "Dashboard",
  "/secrets": "Secrets détectés",
  "/endpoints": "Endpoints détectés",
  "/ai-analysis": "Analyse IA",
  "/report": "Rapport final",
  "/about": "À propos",
};

export default function Navbar() {
  const location = useLocation();
  const title = titles[location.pathname] || "SecretHunter Android";

  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/80 bg-white/78 backdrop-blur-2xl">
      <div className="flex items-center justify-between px-4 py-4 md:px-6">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-blue-700/70">Mobile App Security Lab</p>
          <h2 className="text-xl font-semibold text-slate-950">{title}</h2>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50/90 px-3 py-2 text-sm font-medium text-emerald-700 md:flex">
            <ShieldCheck className="h-4 w-4" />
            Scanner actif
          </div>

          <div className="hidden items-center gap-2 rounded-xl border border-slate-200 bg-white/90 px-3 py-2 text-sm text-slate-600 shadow-sm md:flex">
            <Server className="h-4 w-4 text-blue-600" />
            Mode démo
          </div>

          <Link to="/upload" className="inline-flex items-center gap-2 rounded-xl bg-slate-950 px-4 py-2 text-sm font-semibold text-white shadow-lg shadow-slate-950/20 hover:bg-blue-700">
            <Plus className="h-4 w-4" />
            Nouvelle analyse
          </Link>
        </div>
      </div>
    </header>
  );
}
