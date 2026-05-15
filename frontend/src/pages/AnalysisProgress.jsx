import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Circle, Loader2, AlertTriangle } from "lucide-react";
import { getAnalysisStatus, getAnalysisResults } from "../api/analysisApi";
import { saveAnalysisResult } from "../utils/analysisResultStore";

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
  const [progress, setProgress] = useState(10);
  const [status, setStatus] = useState("running");
  const [message, setMessage] = useState("Analyse en cours...");
  const [error, setError] = useState("");

  const analysisId = sessionStorage.getItem("analysisId");
  const apkName = sessionStorage.getItem("apkName") || "APK en cours";

  useEffect(() => {
    if (!analysisId) {
      setStatus("failed");
      setError("Aucun analysisId trouvé. Veuillez relancer une analyse.");
      return;
    }

    const interval = setInterval(async () => {
      try {
        const statusResponse = await getAnalysisStatus(analysisId);

        setStatus(statusResponse.status);
        setProgress(statusResponse.progress || 0);
        setMessage(statusResponse.message || "Analyse en cours...");

        if (statusResponse.status === "completed") {
          clearInterval(interval);

          const results = await getAnalysisResults(analysisId);
          saveAnalysisResult(results);

          setProgress(100);
          setMessage("Analyse terminée. Résultats disponibles.");
        }

        if (statusResponse.status === "failed") {
          clearInterval(interval);
          setError(statusResponse.error || "L’analyse a échoué.");
        }
      } catch (err) {
        clearInterval(interval);
        setStatus("failed");
        setError(
          err?.response?.data?.message ||
            "Impossible de récupérer le statut depuis le backend."
        );
      }
    }, 1200);

    return () => clearInterval(interval);
  }, [analysisId]);

  const currentStep = Math.min(
    Math.floor((progress / 100) * steps.length),
    steps.length
  );

  const finished = status === "completed";

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Analyse en cours</h1>
        <p className="mt-2 text-zinc-400">APK : {apkName}</p>
      </div>

      <div className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-6">
        <div className="mb-3 flex justify-between">
          <p className="font-medium text-white">{message}</p>
          <p className="text-sm text-zinc-400">{Math.round(progress)}%</p>
        </div>

        <div className="h-3 rounded-full bg-zinc-800">
          <div
            className="h-3 rounded-full bg-red-600 transition-all"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-3 rounded-2xl border border-red-500/30 bg-red-500/10 p-4 text-red-200">
          <AlertTriangle className="h-5 w-5" />
          <p className="text-sm">{error}</p>
        </div>
      )}

      <div className="space-y-3">
        {steps.map((step, index) => {
          const done = index < currentStep;
          const running = index === currentStep && !finished && !error;

          return (
            <div
              key={step}
              className="flex items-center gap-4 rounded-2xl border border-zinc-800 bg-[#1f1f1f] p-4"
            >
              {done && <CheckCircle2 className="h-6 w-6 text-green-400" />}
              {running && (
                <Loader2 className="h-6 w-6 animate-spin text-red-300" />
              )}
              {!done && !running && <Circle className="h-6 w-6 text-zinc-600" />}
              <p className="font-medium text-white">{step}</p>
            </div>
          );
        })}
      </div>

      {finished && (
        <Link
          to="/dashboard"
          className="block rounded-2xl bg-red-600 px-5 py-3 text-center font-medium text-white hover:bg-red-500"
        >
          Voir les résultats réels
        </Link>
      )}
    </div>
  );
}