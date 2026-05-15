import { Link } from "react-router-dom";
import { ArrowRight, Brain, KeyRound, Network, ShieldCheck } from "lucide-react";

const features = [
  { title: "Détection des secrets", description: "API keys, tokens, mots de passe et secrets codés en dur.", icon: KeyRound },
  { title: "Analyse des endpoints", description: "URLs, domaines, IP internes et endpoints backend.", icon: Network },
  { title: "Scoring du risque", description: "Classification du risque : faible, moyen, élevé ou critique.", icon: ShieldCheck },
  { title: "Analyse IA", description: "Explications et recommandations générées automatiquement.", icon: Brain },
];

export default function Home() {
  return (
    <div className="space-y-8">
      <section className="rounded-3xl border border-zinc-800 bg-gradient-to-br from-[#1f1f1f] to-[#111111] p-8 md:p-12">
        <h1 className="text-4xl font-bold text-white md:text-6xl">SecretHunter Android</h1>
        <p className="mt-4 text-xl text-zinc-300">Plateforme intelligente d’analyse statique des APK Android.</p>
        <p className="mt-4 max-w-3xl text-zinc-400">
          Importez un fichier APK, détectez les secrets exposés, identifiez les endpoints sensibles et obtenez une analyse de risque assistée par IA.
        </p>
        <Link to="/upload" className="mt-8 inline-flex items-center gap-2 rounded-2xl bg-red-600 px-5 py-3 font-medium text-white hover:bg-red-500">
          Analyser un APK
          <ArrowRight className="h-5 w-5" />
        </Link>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {features.map((feature) => {
          const Icon = feature.icon;
          return (
            <div key={feature.title} className="rounded-2xl border border-zinc-800 bg-[#1f1f1f] p-5">
              <Icon className="mb-4 h-7 w-7 text-red-300" />
              <h3 className="font-semibold text-white">{feature.title}</h3>
              <p className="mt-2 text-sm text-zinc-400">{feature.description}</p>
            </div>
          );
        })}
      </section>

      <section className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-6">
        <h2 className="text-2xl font-semibold text-white">Flux global</h2>
        <div className="mt-5 grid gap-3 md:grid-cols-5">
          {["Upload APK", "Décompilation", "Analyse statique", "IA Risk Analyzer", "Rapport"].map((step, index) => (
            <div key={step} className="rounded-2xl border border-zinc-800 bg-[#171717] p-4">
              <p className="text-xs text-zinc-500">Étape {index + 1}</p>
              <p className="mt-2 font-medium text-white">{step}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
