import { Link } from "react-router-dom";
import {
  ArrowRight,
  Brain,
  KeyRound,
  LockKeyhole,
  Network,
  ShieldCheck,
  Smartphone,
} from "lucide-react";

const features = [
  {
    title: "Secrets embarques",
    description: "Detection de tokens, API keys, mots de passe et credentials dans l'APK.",
    icon: KeyRound,
  },
  {
    title: "Surface reseau",
    description: "Extraction des URLs, domaines, IP et endpoints backend exposes.",
    icon: Network,
  },
  {
    title: "Risque mobile",
    description: "Score global oriente Android: faible, moyen, eleve ou critique.",
    icon: ShieldCheck,
  },
  {
    title: "Recommandations IA",
    description: "Explications claires et actions de remediation pour le rapport final.",
    icon: Brain,
  },
];

export default function Home() {
  return (
    <div className="space-y-6">
      <section className="mobile-hero overflow-hidden rounded-[2rem] border border-white/70 bg-white/78 p-6 shadow-2xl shadow-blue-950/10 backdrop-blur-2xl md:p-10">
        <div className="grid gap-8 lg:grid-cols-[1.1fr_0.9fr] lg:items-center">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.22em] text-emerald-700">
              <ShieldCheck className="h-4 w-4" />
              Android offensive security
            </div>

            <h1 className="mt-5 max-w-4xl text-5xl font-black tracking-tight text-slate-950 md:text-7xl">
              SecretHunter Android
            </h1>
            <p className="mt-5 max-w-2xl text-xl leading-8 text-slate-600">
              Une plateforme d'audit APK qui transforme une analyse statique en
              lecture claire: secrets, endpoints, score de risque et rapport IA.
            </p>

            <div className="mt-8 flex flex-wrap gap-3">
              <Link
                to="/upload"
                className="inline-flex items-center gap-2 rounded-2xl bg-slate-950 px-6 py-3 font-bold text-white shadow-xl shadow-slate-950/20 hover:bg-blue-700"
              >
                Analyser un APK
                <ArrowRight className="h-5 w-5" />
              </Link>
              <Link
                to="/dashboard"
                className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white/80 px-6 py-3 font-bold text-slate-800 shadow-sm hover:bg-blue-50"
              >
                Voir le dashboard
              </Link>
            </div>
          </div>

          <div className="relative mx-auto w-full max-w-sm">
            <div className="phone-radar" />
            <div className="phone-shell">
              <div className="phone-top" />
              <div className="phone-screen">
                <div className="scan-beam" />
                <div className="flex items-center justify-between">
                  <Smartphone className="h-10 w-10 text-blue-700" />
                  <LockKeyhole className="h-9 w-9 text-red-500" />
                </div>
                <p className="mt-8 text-xs font-bold uppercase tracking-[0.22em] text-blue-600">
                  APK Risk Score
                </p>
                <p className="mt-2 text-6xl font-black text-slate-950">86</p>
                <p className="text-sm font-semibold text-red-600">Risque critique detecte</p>

                <div className="mt-8 space-y-3">
                  {["Hardcoded API key", "Endpoint non documente", "Permission sensible"].map((item) => (
                    <div key={item} className="rounded-2xl border border-slate-200 bg-white/80 p-3 font-semibold text-slate-800">
                      {item}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {features.map((feature) => {
          const Icon = feature.icon;
          return (
            <div key={feature.title} className="rounded-2xl border border-slate-200 bg-white/82 p-5 shadow-xl shadow-blue-950/5 backdrop-blur-2xl">
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-blue-50">
                <Icon className="h-6 w-6 text-blue-700" />
              </div>
              <h3 className="mt-5 font-black text-slate-950">{feature.title}</h3>
              <p className="mt-2 text-sm leading-6 text-slate-600">{feature.description}</p>
            </div>
          );
        })}
      </section>

      <section className="security-panel rounded-[2rem] border border-slate-200 bg-slate-950 p-6 text-white shadow-2xl shadow-slate-950/20">
        <div className="grid gap-3 md:grid-cols-5">
          {["Upload APK", "Decompilation", "Analyse statique", "IA Risk Analyzer", "Rapport"].map((step, index) => (
            <div key={step} className="rounded-2xl border border-white/10 bg-white/5 p-4">
              <p className="font-mono text-xs text-blue-200">Etape 0{index + 1}</p>
              <p className="mt-2 font-bold text-white">{step}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
