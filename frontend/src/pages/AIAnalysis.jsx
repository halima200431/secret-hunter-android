import { Brain, CheckCircle2 } from "lucide-react";
import { getAnalysisResult } from "../utils/analysisResultStore";

export default function AIAnalysis() {
  const data = mockAnalysisResult;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Analyse IA</h1>
        <p className="mt-2 text-zinc-400">Classification du risque et recommandations automatiques.</p>
      </div>

      <section className="rounded-3xl border border-red-500/20 bg-red-500/10 p-6">
        <div className="mb-4 flex items-center gap-3">
          <Brain className="h-7 w-7 text-red-200" />
          <h2 className="text-2xl font-semibold text-white">Résumé automatique</h2>
        </div>
        <p className="leading-7 text-zinc-200">{data.aiSummary}</p>
      </section>

      <section className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-6">
        <div className="mb-5 flex items-center gap-3">
          <CheckCircle2 className="h-6 w-6 text-green-300" />
          <h2 className="text-xl font-semibold text-white">Recommandations prioritaires</h2>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          {data.recommendations.map((rec) => (
            <div key={rec.title} className="rounded-2xl border border-zinc-800 bg-[#171717] p-4">
              <p className="text-xs font-medium uppercase tracking-wider text-red-300">Priorité {rec.priority}</p>
              <h3 className="mt-2 font-semibold text-white">{rec.title}</h3>
              <p className="mt-2 text-sm leading-6 text-zinc-400">{rec.description}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
