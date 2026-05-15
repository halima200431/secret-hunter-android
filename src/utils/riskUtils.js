export const RISK_LEVELS = {
  Low: { label: "Faible", color: "text-risk-low", bg: "bg-risk-low/10", border: "border-risk-low/30", hex: "#22c55e" },
  Medium: { label: "Moyen", color: "text-risk-medium", bg: "bg-risk-medium/10", border: "border-risk-medium/30", hex: "#f59e0b" },
  High: { label: "Élevé", color: "text-risk-high", bg: "bg-risk-high/10", border: "border-risk-high/30", hex: "#f97316" },
  Critical: { label: "Critique", color: "text-risk-critical", bg: "bg-risk-critical/10", border: "border-risk-critical/30", hex: "#ef4444" },
};

export const getRiskConfig = (risk) => {
  return RISK_LEVELS[risk] || RISK_LEVELS["Low"];
};

export const getRiskScore = (score) => {
  if (score <= 30) return "Low";
  if (score <= 55) return "Medium";
  if (score <= 75) return "High";
  return "Critical";
};

export const RISK_CHART_COLORS = {
  Faible: "#22c55e",
  Moyen: "#f59e0b",
  Élevé: "#f97316",
  Critique: "#ef4444",
};
