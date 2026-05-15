import { AlertTriangle, FileSearch, KeyRound, Network } from "lucide-react";
import mockAnalysisResult from "../data/mockAnalysisResult";

function Card({ title, value, icon: Icon }) {
  return (
    <div className="rounded-2xl border border-zinc-800 bg-[#1f1f1f] p-5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-zinc-400">{title}</p>
          <p className="mt-2 text-3xl font-bold text-white">{value}</p>
        </div>
        <Icon className="h-7 w-7 text-red-300" />
      </div>
    </div>
  );
}

export default function Dashboard() {
  const data = mockAnalysisResult;
  const apkName = sessionStorage.getItem("apkName") || data.apkName;

  return (
    <div className="space-y-6">
      <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
        <div>
          <h1 className="text-3xl font-bold text-white">Dashboard</h1>
          <p className="mt-2 text-zinc-400">Résultats de l’analyse de : {apkName}</p>
        </div>

        <div className="rounded-2xl border border-red-500/30 bg-red-500/10 px-5 py-3 text-red-200">
          <p className="text-sm">Risque global</p>
          <p className="text-2xl font-bold">{data.globalRisk}</p>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Card title="Secrets détectés" value={data.secretsCount} icon={KeyRound} />
        <Card title="Endpoints détectés" value={data.endpointsCount} icon={Network} />
        <Card title="Fichiers analysés" value={data.filesAnalyzed} icon={FileSearch} />
        <Card title="Score global" value={`${data.globalScore}/100`} icon={AlertTriangle} />
      </div>

      <div className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-6">
        <h2 className="text-xl font-semibold text-white">Résumé IA</h2>
        <p className="mt-3 leading-7 text-zinc-400">{data.aiSummary}</p>
      </div>

      <div className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-6">
        <h2 className="text-xl font-semibold text-white">Distribution des risques</h2>
        <div className="mt-5 grid gap-3 md:grid-cols-4">
          {data.riskDistribution.map((item) => (
            <div key={item.name} className="rounded-2xl border border-zinc-800 bg-[#171717] p-4">
              <p className="text-sm text-zinc-400">{item.name}</p>
              <p className="mt-2 text-3xl font-bold text-white">{item.value}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
