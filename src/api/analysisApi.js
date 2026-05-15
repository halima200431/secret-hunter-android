/**
 * analysisApi.js
 * Couche d'abstraction pour les appels au backend Flask/FastAPI.
 *
 * MODE MOCK : USE_MOCK = true → retourne des données de démonstration.
 * MODE RÉEL : Mettre USE_MOCK = false et définir BACKEND_URL.
 *
 * Pour connecter le backend plus tard :
 * 1. Passer USE_MOCK à false
 * 2. Définir BACKEND_URL (ex: http://localhost:5000)
 * 3. S'assurer que Flask/FastAPI expose les routes décrites ci-dessous
 */

import axios from "axios";
import mockAnalysisResult from "../data/mockAnalysisResult.js";

// ─── Configuration ──────────────────────────────────────────────────────────
export const USE_MOCK = true;
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";

const api = axios.create({
  baseURL: BACKEND_URL,
  timeout: 30000,
  headers: { "Content-Type": "application/json" },
});

// ─── Helpers ─────────────────────────────────────────────────────────────────
const mockDelay = (ms = 800) => new Promise((r) => setTimeout(r, ms));

// ─── API Functions ───────────────────────────────────────────────────────────

/**
 * Upload APK pour analyse
 * POST /api/analyze
 * @param {File} file - Fichier APK
 * @returns {{ analysisId: string }}
 */
export const uploadApk = async (file) => {
  if (USE_MOCK) {
    await mockDelay(1200);
    return { analysisId: "mock-analysis-001" };
  }
  const formData = new FormData();
  formData.append("apk", file);
  const res = await api.post("/api/analyze", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return res.data;
};

/**
 * Récupérer le statut de l'analyse
 * GET /api/analysis/{analysisId}/status
 * @param {string} analysisId
 * @returns {{ status: string, progress: number, currentStep: string }}
 */
export const getAnalysisStatus = async (analysisId) => {
  if (USE_MOCK) {
    await mockDelay(500);
    return { status: "completed", progress: 100, currentStep: "done" };
  }
  const res = await api.get(`/api/analysis/${analysisId}/status`);
  return res.data;
};

/**
 * Récupérer les résultats complets de l'analyse
 * GET /api/analysis/{analysisId}/results
 * @param {string} analysisId
 * @returns {object} - Résultats complets (voir mockAnalysisResult.js pour le format)
 */
export const getAnalysisResults = async (analysisId) => {
  if (USE_MOCK) {
    await mockDelay(600);
    return mockAnalysisResult;
  }
  const res = await api.get(`/api/analysis/${analysisId}/results`);
  return res.data;
};

/**
 * Télécharger le rapport PDF
 * GET /api/analysis/{analysisId}/report/pdf
 * @param {string} analysisId
 */
export const downloadPdfReport = async (analysisId) => {
  if (USE_MOCK) {
    await mockDelay(500);
    alert("[Mode démo] Le téléchargement PDF sera disponible une fois le backend connecté.");
    return;
  }
  const res = await api.get(`/api/analysis/${analysisId}/report/pdf`, {
    responseType: "blob",
  });
  const url = window.URL.createObjectURL(new Blob([res.data]));
  const link = document.createElement("a");
  link.href = url;
  link.setAttribute("download", `SecretHunter_Report_${analysisId}.pdf`);
  document.body.appendChild(link);
  link.click();
  link.remove();
};

/**
 * Télécharger le rapport JSON
 * GET /api/analysis/{analysisId}/report/json
 * @param {string} analysisId
 */
export const downloadJsonReport = async (analysisId) => {
  if (USE_MOCK) {
    const blob = new Blob([JSON.stringify(mockAnalysisResult, null, 2)], {
      type: "application/json",
    });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", "SecretHunter_Report_mock.json");
    document.body.appendChild(link);
    link.click();
    link.remove();
    return;
  }
  const res = await api.get(`/api/analysis/${analysisId}/report/json`, {
    responseType: "blob",
  });
  const url = window.URL.createObjectURL(new Blob([res.data]));
  const link = document.createElement("a");
  link.href = url;
  link.setAttribute("download", `SecretHunter_Report_${analysisId}.json`);
  document.body.appendChild(link);
  link.click();
  link.remove();
};
