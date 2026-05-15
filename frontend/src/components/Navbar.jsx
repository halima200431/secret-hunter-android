import { Link, useLocation } from "react-router-dom";
import { Plus, Server } from "lucide-react";

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
    <header className="sticky top-0 z-30 border-b border-zinc-800 bg-[#171717]/90 backdrop-blur">
      <div className="flex items-center justify-between px-4 py-4 md:px-6">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-zinc-500">SecretHunter Android</p>
          <h2 className="text-xl font-semibold text-white">{title}</h2>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-2 rounded-xl border border-zinc-800 bg-[#1f1f1f] px-3 py-2 text-sm text-zinc-300 md:flex">
            <Server className="h-4 w-4" />
            Mode démo
          </div>

          <Link to="/upload" className="inline-flex items-center gap-2 rounded-xl bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500">
            <Plus className="h-4 w-4" />
            Nouvelle analyse
          </Link>
        </div>
      </div>
    </header>
  );
}
