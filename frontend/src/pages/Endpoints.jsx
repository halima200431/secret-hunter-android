import { getAnalysisResult } from "../utils/analysisResultStore";

function Badge({ risk }) {
  const color =
    risk === "Critical"
      ? "border-red-500/30 bg-red-500/10 text-red-200"
      : risk === "High"
      ? "border-orange-500/30 bg-orange-500/10 text-orange-200"
      : "border-yellow-500/30 bg-yellow-500/10 text-yellow-200";

  return <span className={`rounded-full border px-3 py-1 text-xs ${color}`}>{risk}</span>;
}

export default function Endpoints() {
  const data = getAnalysisResult().endpoints || [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Endpoints détectés</h1>
        <p className="mt-2 text-zinc-400">URLs, domaines, IP internes et endpoints backend.</p>
      </div>

      <div className="overflow-hidden rounded-3xl border border-zinc-800 bg-[#1f1f1f]">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead className="border-b border-zinc-800 bg-[#111111] text-zinc-400">
              <tr>
                <th className="p-4">URL</th>
                <th className="p-4">Type</th>
                <th className="p-4">Protocole</th>
                <th className="p-4">Fichier</th>
                <th className="p-4">Ligne</th>
                <th className="p-4">Risque</th>
              </tr>
            </thead>
            <tbody>
              {data.map((item) => (
                <tr key={item.id} className="border-b border-zinc-800 last:border-0">
                  <td className="p-4 font-mono text-zinc-200">{item.url}</td>
                  <td className="p-4 text-white">{item.type}</td>
                  <td className="p-4 text-zinc-300">{item.protocol}</td>
                  <td className="p-4 text-zinc-300">{item.file}</td>
                  <td className="p-4 text-zinc-400">{item.line}</td>
                  <td className="p-4"><Badge risk={item.risk} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
