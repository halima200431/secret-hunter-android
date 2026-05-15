import mockAnalysisResult from "../data/mockAnalysisResult";

const STORAGE_KEY = "latestAnalysisResult";

export function saveAnalysisResult(result) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(result));
}

export function getAnalysisResult() {
  const stored = localStorage.getItem(STORAGE_KEY);

  if (!stored) {
    return mockAnalysisResult;
  }

  try {
    return JSON.parse(stored);
  } catch {
    return mockAnalysisResult;
  }
}

export function clearAnalysisResult() {
  localStorage.removeItem(STORAGE_KEY);
}