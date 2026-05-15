import { Download, FileText } from "lucide-react";
import { getAnalysisResult } from "../utils/analysisResultStore";

export default function Report() {
  const data = getAnalysisResult();

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "secrethunter-report.json";
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
        <div>
          <h1 className="text-3xl font-bold text-white">Rapport final</h1>
          <p className="mt-2 text-zinc-400">Aperçu du rapport de sécurité.</p>
        </div>

        <button onClick={downloadJson} className="inline-flex items-center gap-2 rounded-2xl bg-red-600 px-4 py-3 text-sm font-medium text-white hover:bg-red-500">
          <Download className="h-4 w-4" />
          Télécharger JSON
        </button>
      </div>

      <article className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-8">
        <div className="mb-8 flex items-center gap-3">
          <FileText className="h-8 w-8 text-red-300" />
          <div>
            <h2 className="text-2xl font-bold text-white">SecretHunter Android Report</h2>
            <p className="text-zinc-500">{data.apkName}</p>
          </div>
        </div>

        <section className="space-y-3 border-b border-zinc-800 pb-6">
          <h3 className="text-xl font-semibold text-white">1. Résumé</h3>
          <p className="text-zinc-400">{data.aiSummary}</p>
          <p className="text-zinc-400">Score global : {data.globalScore}/100</p>
          <p className="text-zinc-400">Risque global : {data.globalRisk}</p>
        </section>

        <section className="space-y-3 border-b border-zinc-800 py-6">
          <h3 className="text-xl font-semibold text-white">2. Secrets détectés</h3>
          <p className="text-zinc-400">Total : {data.secretsCount}</p>
        </section>

        <section className="space-y-3 border-b border-zinc-800 py-6">
          <h3 className="text-xl font-semibold text-white">3. Endpoints détectés</h3>
          <p className="text-zinc-400">Total : {data.endpointsCount}</p>
        </section>

        <section className="space-y-3 pt-6">
          <h3 className="text-xl font-semibold text-white">4. Recommandations</h3>
          {data.recommendations.map((rec) => (
            <div key={rec.title} className="rounded-2xl border border-zinc-800 bg-[#171717] p-4">
              <p className="font-medium text-white">{rec.title}</p>
              <p className="mt-1 text-zinc-400">{rec.description}</p>
            </div>
          ))}
        </section>
      </article>
    </div>
  );
}
