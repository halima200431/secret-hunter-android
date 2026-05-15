import React from "react";
import { getRiskConfig } from "../utils/riskUtils";

const RiskBadge = ({ risk, size = "sm" }) => {
  const config = getRiskConfig(risk);
  const sizeClass = size === "lg" ? "px-3 py-1 text-sm font-semibold" : "px-2 py-0.5 text-xs font-medium";

  return (
    <span
      className={`inline-flex items-center rounded-md border ${config.bg} ${config.color} ${config.border} ${sizeClass} font-mono tracking-wide`}
    >
      {config.label}
    </span>
  );
};

export default RiskBadge;
