import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Circle, Loader2 } from "lucide-react";

const steps = [
  "Upload de l’APK",
  "Validation du fichier",
  "Décompilation",
  "Extraction des fichiers",
  "Scan des secrets",
  "Scan des endpoints",
  "Analyse IA",
  "Génération du rapport",
];

export default function AnalysisProgress() {
  const [current, setCurrent] = useState(0);
  const apkName = sessionStorage.getItem("apkName") || "demo-vulnerable-app.apk";
  const finished = current >= steps.length;
  const progress = Math.min((current / steps.length) * 100, 100);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrent((old) => {
        if (old >= steps.length) {
          clearInterval(timer);
          return old;
        }
        return old + 1;
      });
    }, 800);

    return () => clearInterval(timer);
  }, []);

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Analyse en cours</h1>
        <p className="mt-2 text-zinc-400">APK : {apkName}</p>
      </div>

      <div className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-6">
        <div className="mb-3 flex justify-between">
          <p className="font-medium text-white">{finished ? "Analyse terminée" : "Analyse en cours..."}</p>
          <p className="text-sm text-zinc-400">{Math.round(progress)}%</p>
        </div>
        <div className="h-3 rounded-full bg-zinc-800">
          <div className="h-3 rounded-full bg-red-600 transition-all" style={{ width: `${progress}%` }} />
        </div>
      </div>

      <div className="space-y-3">
        {steps.map((step, index) => {
          const done = index < current;
          const running = index === current && !finished;

          return (
            <div key={step} className="flex items-center gap-4 rounded-2xl border border-zinc-800 bg-[#1f1f1f] p-4">
              {done && <CheckCircle2 className="h-6 w-6 text-green-400" />}
              {running && <Loader2 className="h-6 w-6 animate-spin text-red-300" />}
              {!done && !running && <Circle className="h-6 w-6 text-zinc-600" />}
              <p className="font-medium text-white">{step}</p>
            </div>
          );
        })}
      </div>

      {finished && (
        <Link to="/dashboard" className="block rounded-2xl bg-red-600 px-5 py-3 text-center font-medium text-white hover:bg-red-500">
          Voir les résultats
        </Link>
      )}
    </div>
  );
}
