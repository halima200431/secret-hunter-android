import { NavLink } from "react-router-dom";
import { Shield, LayoutDashboard, Upload, KeyRound, Network, Brain, FileText, Info } from "lucide-react";

const items = [
  { label: "Dashboard", path: "/dashboard", icon: LayoutDashboard },
  { label: "Upload APK", path: "/upload", icon: Upload },
  { label: "Secrets", path: "/secrets", icon: KeyRound },
  { label: "Endpoints", path: "/endpoints", icon: Network },
  { label: "Analyse IA", path: "/ai-analysis", icon: Brain },
  { label: "Rapport", path: "/report", icon: FileText },
  { label: "À propos", path: "/about", icon: Info },
];

export default function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 hidden h-screen w-64 border-r border-zinc-800 bg-[#111111] lg:block">
      <div className="border-b border-zinc-800 p-5">
        <NavLink to="/" className="flex items-center gap-3">
          <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-2">
            <Shield className="h-6 w-6 text-red-300" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">SecretHunter</h1>
            <p className="text-xs text-zinc-500">Android Scanner</p>
          </div>
        </NavLink>
      </div>

      <nav className="space-y-2 p-4">
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-xl px-4 py-3 text-sm transition ${
                  isActive
                    ? "border border-red-500/30 bg-red-500/10 text-red-200"
                    : "text-zinc-400 hover:bg-white/5 hover:text-white"
                }`
              }
            >
              <Icon className="h-5 w-5" />
              {item.label}
            </NavLink>
          );
        })}
      </nav>
    </aside>
  );
}
