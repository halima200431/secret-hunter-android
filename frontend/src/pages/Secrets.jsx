import { getAnalysisResult } from "../utils/analysisResultStore";

function Badge({ risk }) {
  const value = String(risk || "").toLowerCase();

  const color =
    value.includes("critical") || value.includes("critique")
      ? "border-red-500/30 bg-red-500/10 text-red-200"
      : value.includes("high") || value.includes("élevé")
      ? "border-orange-500/30 bg-orange-500/10 text-orange-200"
      : value.includes("medium") || value.includes("moyen")
      ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-200"
      : "border-green-500/30 bg-green-500/10 text-green-200";

  return (
    <span className={`rounded-full border px-3 py-1 text-xs ${color}`}>
      {risk || "Low"}
    </span>
  );
}

export default function Secrets() {
  const analysisResult = getAnalysisResult();
  const data = Array.isArray(analysisResult?.secrets)
    ? analysisResult.secrets
    : [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Secrets détectés</h1>
        <p className="mt-2 text-zinc-400">
          Tokens, API keys, mots de passe et secrets codés en dur.
        </p>
      </div>

      {data.length === 0 ? (
        <div className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-8 text-center">
          <h2 className="text-xl font-semibold text-white">
            Aucun secret détecté
          </h2>
          <p className="mt-3 text-zinc-400">
            L’analyse de cet APK n’a pas trouvé de token, clé API, mot de passe ou secret exposé.
          </p>
          <p className="mt-2 text-sm text-zinc-500">
            Cela peut être normal si l’application ne contient pas de secrets codés en dur, ou si les règles de détection doivent être enrichies.
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-3xl border border-zinc-800 bg-[#1f1f1f]">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="border-b border-zinc-800 bg-[#111111] text-zinc-400">
                <tr>
                  <th className="p-4">Type</th>
                  <th className="p-4">Valeur masquée</th>
                  <th className="p-4">Fichier</th>
                  <th className="p-4">Ligne</th>
                  <th className="p-4">Risque</th>
                  <th className="p-4">Recommandation</th>
                </tr>
              </thead>

              <tbody>
                {data.map((item, index) => (
                  <tr
                    key={item.id || index}
                    className="border-b border-zinc-800 last:border-0 hover:bg-white/[0.03]"
                  >
                    <td className="p-4 font-medium text-white">
                      {item.type || "Secret"}
                    </td>

                    <td className="p-4 font-mono text-red-200">
                      {item.maskedValue || "********"}
                    </td>

                    <td className="p-4 text-zinc-300">
                      {item.file || "unknown"}
                    </td>

                    <td className="p-4 text-zinc-400">
                      {item.line || "-"}
                    </td>

                    <td className="p-4">
                      <Badge risk={item.risk} />
                    </td>

                    <td className="p-4 text-zinc-400">
                      {item.recommendation ||
                        "Vérifier cette valeur et éviter de stocker des secrets dans le code client."}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}