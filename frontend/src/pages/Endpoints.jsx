import { getAnalysisResult } from "../utils/analysisResultStore";

function getEndpointValue(item) {
  return item?.url || item?.value || item?.endpoint || "";
}

function getProtocol(item) {
  const value = getEndpointValue(item).toLowerCase();

  if (item?.protocol) {
    return item.protocol;
  }

  if (value.startsWith("https://")) {
    return "HTTPS";
  }

  if (value.startsWith("http://")) {
    return "HTTP";
  }

  if (item?.type === "DOMAIN") {
    return "DOMAIN";
  }

  if (item?.type === "IP") {
    return "IP";
  }

  return "Unknown";
}

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

export default function Endpoints() {
  const analysisResult = getAnalysisResult();
  const endpoints = Array.isArray(analysisResult?.endpoints)
    ? analysisResult.endpoints
    : [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Endpoints détectés</h1>
        <p className="mt-2 text-zinc-400">
          URLs, domaines, IP internes et endpoints backend détectés dans l’APK.
        </p>
      </div>

      {endpoints.length === 0 ? (
        <div className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-8 text-center">
          <h2 className="text-xl font-semibold text-white">
            Aucun endpoint détecté
          </h2>
          <p className="mt-3 text-zinc-400">
            L’analyse n’a trouvé aucune URL, domaine ou adresse IP dans les fichiers extraits.
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-3xl border border-zinc-800 bg-[#1f1f1f]">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1000px] text-left text-sm">
              <thead className="border-b border-zinc-800 bg-[#111111] text-zinc-400">
                <tr>
                  <th className="p-4">URL / Domaine / IP</th>
                  <th className="p-4">Type</th>
                  <th className="p-4">Protocole</th>
                  <th className="p-4">Fichier</th>
                  <th className="p-4">Ligne</th>
                  <th className="p-4">Risque</th>
                </tr>
              </thead>

              <tbody>
                {endpoints.map((item, index) => {
                  const endpointValue = getEndpointValue(item);
                  const protocol = getProtocol(item);

                  return (
                    <tr
                      key={item.id || `${endpointValue}-${index}`}
                      className="border-b border-zinc-800 last:border-0 hover:bg-white/[0.03]"
                    >
                      <td className="max-w-[360px] break-all p-4 font-mono text-red-200">
                        {endpointValue || "Valeur inconnue"}
                      </td>

                      <td className="p-4 font-medium text-white">
                        {item.type || "Endpoint"}
                      </td>

                      <td className="p-4 text-zinc-300">
                        {protocol}
                      </td>

                      <td className="max-w-[320px] break-all p-4 text-zinc-300">
                        {item.file || "unknown"}
                      </td>

                      <td className="p-4 text-zinc-400">
                        {item.line || "-"}
                      </td>

                      <td className="p-4">
                        <Badge risk={item.risk || item.severity} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}