import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  CheckCircle2,
  FileArchive,
  Fingerprint,
  LockKeyhole,
  Radar,
  ShieldCheck,
  Smartphone,
  UploadCloud,
  Wifi,
} from "lucide-react";
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
      setError("Le fichier doit avoir l'extension .apk.");
      setFile(null);
      return;
    }

    setError("");
    setFile(selectedFile);
  };

  const startAnalysis = async () => {
    if (!file) {
      setError("Veuillez choisir un fichier APK avant de lancer l'analyse.");
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
        "Impossible d'envoyer l'APK au backend. Verifiez que le backend est lance.";

      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const auditCards = [
    { label: "Secrets", value: "API keys", icon: LockKeyhole },
    { label: "Reseau", value: "Endpoints", icon: Wifi },
    { label: "IA", value: "Recommandations", icon: Fingerprint },
  ];

  const pipeline = [
    "Decompilation APK",
    "Extraction secrets",
    "Analyse endpoints",
    "Score de risque IA",
  ];

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <section className="mobile-hero overflow-hidden rounded-[2rem] border border-white/70 bg-white/78 p-6 shadow-2xl shadow-blue-950/10 backdrop-blur-2xl md:p-8">
        <div className="grid gap-8 lg:grid-cols-[1.05fr_0.95fr] lg:items-center">
          <div className="space-y-6">
            <div className="inline-flex items-center gap-2 rounded-full border border-blue-200 bg-blue-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.22em] text-blue-700">
              <Radar className="h-4 w-4" />
              Mobile threat scanner
            </div>

            <div>
              <h1 className="max-w-3xl text-4xl font-black tracking-tight text-slate-950 md:text-6xl">
                Analysez la securite d'une app Android comme en laboratoire.
              </h1>
              <p className="mt-4 max-w-2xl text-lg leading-8 text-slate-600">
                Importez un APK, detectez les secrets exposes, cartographiez les
                endpoints et generez un score de risque pret a presenter.
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              {auditCards.map((item) => {
                const Icon = item.icon;
                return (
                  <div
                    key={item.label}
                    className="rounded-2xl border border-slate-200 bg-white/78 p-4 shadow-sm"
                  >
                    <Icon className="h-5 w-5 text-blue-700" />
                    <p className="mt-3 text-xs font-bold uppercase tracking-[0.18em] text-slate-400">
                      {item.label}
                    </p>
                    <p className="mt-1 font-semibold text-slate-900">
                      {item.value}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="relative mx-auto w-full max-w-md">
            <div className="phone-radar" />
            <div className="phone-shell">
              <div className="phone-top" />
              <div className="phone-screen">
                <div className="scan-beam" />
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-bold uppercase tracking-[0.22em] text-blue-600">
                      APK Shield
                    </p>
                    <p className="mt-1 text-2xl font-black text-slate-950">
                      Protection mobile
                    </p>
                  </div>
                  <ShieldCheck className="h-10 w-10 text-emerald-500" />
                </div>

                <div className="mt-8 rounded-3xl border border-blue-100 bg-blue-50/70 p-5">
                  <Smartphone className="h-11 w-11 text-blue-700" />
                  <div className="mt-5 space-y-3">
                    <div className="h-2 rounded-full bg-blue-200">
                      <div className="h-2 w-4/5 rounded-full bg-blue-700" />
                    </div>
                    <div className="h-2 rounded-full bg-emerald-100">
                      <div className="h-2 w-2/3 rounded-full bg-emerald-500" />
                    </div>
                    <div className="h-2 rounded-full bg-red-100">
                      <div className="h-2 w-1/3 rounded-full bg-red-500" />
                    </div>
                  </div>
                </div>

                <div className="mt-5 grid grid-cols-2 gap-3">
                  <div className="rounded-2xl border border-slate-200 bg-white/80 p-3">
                    <p className="text-xs text-slate-500">Manifest</p>
                    <p className="font-bold text-slate-950">Permissions</p>
                  </div>
                  <div className="rounded-2xl border border-slate-200 bg-white/80 p-3">
                    <p className="text-xs text-slate-500">Backend</p>
                    <p className="font-bold text-slate-950">HTTPS</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-[1fr_360px]">
        <div className="rounded-[2rem] border border-dashed border-blue-200 bg-white/82 p-6 text-center shadow-xl shadow-blue-950/10 backdrop-blur-2xl md:p-8">
          <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-3xl border border-red-100 bg-red-50 shadow-lg shadow-red-500/10">
            <UploadCloud className="h-10 w-10 text-red-500" />
          </div>

          <h2 className="mt-5 text-2xl font-black text-slate-950">
            Deposer le fichier APK a auditer
          </h2>

          <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-600">
            Le backend Flask lance l'analyse statique: secrets, endpoints, score
            global et recommandations IA.
          </p>

          <label className="mt-7 inline-flex cursor-pointer items-center gap-2 rounded-2xl bg-slate-950 px-6 py-3 font-bold text-white shadow-xl shadow-slate-950/20 hover:bg-blue-700">
            <FileArchive className="h-5 w-5" />
            Choisir un APK
            <input
              type="file"
              accept=".apk"
              className="hidden"
              onChange={(e) => handleFile(e.target.files?.[0])}
            />
          </label>

          {file && (
            <div className="mx-auto mt-6 flex max-w-xl items-center gap-4 rounded-2xl border border-emerald-200 bg-emerald-50/80 p-4 text-left">
              <CheckCircle2 className="h-7 w-7 text-emerald-600" />
              <div>
                <p className="font-bold text-slate-950">{file.name}</p>
                <p className="text-sm text-slate-500">
                  {(file.size / 1024 / 1024).toFixed(2)} MB pret pour analyse
                </p>
              </div>
            </div>
          )}

          {error && (
            <div className="mx-auto mt-6 flex max-w-xl items-center gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-left text-red-700">
              <AlertTriangle className="h-5 w-5" />
              <p className="text-sm font-medium">{error}</p>
            </div>
          )}
        </div>

        <aside className="security-panel rounded-[2rem] border border-slate-200 bg-slate-950 p-6 text-white shadow-2xl shadow-slate-950/20">
          <p className="text-xs font-bold uppercase tracking-[0.24em] text-blue-300">
            Pipeline
          </p>
          <h3 className="mt-2 text-2xl font-black">Audit securite mobile</h3>
          <div className="mt-6 space-y-4">
            {pipeline.map((step, index) => (
              <div
                key={step}
                className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/5 p-3"
              >
                <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-500/20 font-mono text-sm text-blue-200">
                  0{index + 1}
                </span>
                <span className="font-semibold">{step}</span>
              </div>
            ))}
          </div>
        </aside>
      </section>

      <button
        onClick={startAnalysis}
        disabled={loading}
        className="w-full rounded-2xl bg-red-600 px-5 py-4 text-lg font-black text-white shadow-2xl shadow-red-600/25 hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {loading ? "Envoi de l'APK au backend..." : "Lancer l'analyse de securite"}
      </button>
    </div>
  );
}
