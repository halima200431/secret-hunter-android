import axios from "axios";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000/api";

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 120000,
});

export async function uploadApk(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await apiClient.post("/analyze", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
  });

  return response.data;
}

export async function getAnalysisStatus(analysisId) {
  const response = await apiClient.get(`/analysis/${analysisId}/status`);
  return response.data;
}

export async function getAnalysisResults(analysisId) {
  const response = await apiClient.get(`/analysis/${analysisId}/results`);
  return response.data;
}