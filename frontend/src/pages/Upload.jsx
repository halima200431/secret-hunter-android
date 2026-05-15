import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle, FileArchive, UploadCloud } from "lucide-react";
import { uploadApk } from "../api/analysisApi";
import { clearAnalysisResult } from "../utils/analysisResultStore";

export default function Upload() {
  const navigate = useNavigate();

  const [file, setFile] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleFile = (selectedFile) => {
    if (!selectedFile) {
      setError("Veuillez choisir un fichier APK.");
      setFile(null);
      return;
    }

    if (!selectedFile.name.toLowerCase().endsWith(".apk")) {
      setError("Le fichier doit avoir l’extension .apk.");
      setFile(null);
      return;
    }

    setError("");
    setFile(selectedFile);
  };

  const startAnalysis = async () => {
    if (!file) {
      setError("Veuillez choisir un fichier APK avant de lancer l’analyse.");
      return;
    }

    try {
      setLoading(true);
      setError("");

      clearAnalysisResult();

      const response = await uploadApk(file);

      sessionStorage.setItem("analysisId", response.analysisId);
      sessionStorage.setItem("apkName", response.apkName || file.name);

      navigate("/progress");
    } catch (err) {
      const message =
        err?.response?.data?.message ||
        "Impossible d’envoyer l’APK au backend. Vérifiez que le backend est lancé.";

      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Importer un APK</h1>
        <p className="mt-2 text-zinc-400">
          Sélectionnez une application Android à analyser.
        </p>
      </div>

      <div className="rounded-3xl border border-dashed border-zinc-700 bg-[#1f1f1f] p-8 text-center">
        <UploadCloud className="mx-auto h-14 w-14 text-red-300" />

        <h2 className="mt-4 text-xl font-semibold text-white">
          Choisir un fichier APK
        </h2>

        <p className="mt-2 text-sm text-zinc-400">
          Le fichier sera envoyé au backend Flask pour analyse.
        </p>

        <label className="mt-6 inline-flex cursor-pointer rounded-2xl bg-zinc-100 px-5 py-3 font-medium text-zinc-950 hover:bg-white">
          Choisir un APK
          <input
            type="file"
            accept=".apk"
            className="hidden"
            onChange={(e) => handleFile(e.target.files?.[0])}
          />
        </label>

        {file && (
          <div className="mx-auto mt-6 flex max-w-xl items-center gap-3 rounded-2xl border border-zinc-800 bg-[#171717] p-4 text-left">
            <FileArchive className="h-6 w-6 text-red-300" />
            <div>
              <p className="font-medium text-white">{file.name}</p>
              <p className="text-sm text-zinc-500">
                {(file.size / 1024 / 1024).toFixed(2)} MB
              </p>
            </div>
          </div>
        )}

        {error && (
          <div className="mx-auto mt-6 flex max-w-xl items-center gap-3 rounded-2xl border border-red-500/30 bg-red-500/10 p-4 text-left text-red-200">
            <AlertTriangle className="h-5 w-5" />
            <p className="text-sm">{error}</p>
          </div>
        )}
      </div>

      <button
        onClick={startAnalysis}
        disabled={loading}
        className="w-full rounded-2xl bg-red-600 px-5 py-3 font-medium text-white hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {loading ? "Envoi de l’APK au backend..." : "Lancer l’analyse"}
      </button>
    </div>
  );
}