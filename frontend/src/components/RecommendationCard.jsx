import React from "react";
import { AlertTriangle, AlertCircle, Info } from "lucide-react";
import { getRiskConfig } from "../utils/riskUtils";

const ICONS = {
  Critical: AlertCircle,
  High: AlertTriangle,
  Medium: Info,
  Low: Info,
};

const RecommendationCard = ({ priority, title, description }) => {
  const config = getRiskConfig(priority);
  const Icon = ICONS[priority] || Info;

  return (
    <div className={`rounded-xl border p-4 flex gap-4 ${config.bg} ${config.border}`}>
      <div className={`mt-0.5 flex-shrink-0`}>
        <Icon size={18} className={config.color} />
      </div>
      <div className="flex flex-col gap-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={`text-xs font-mono font-semibold uppercase tracking-widest ${config.color}`}>
            {config.label}
          </span>
        </div>
        <p className="text-sm font-semibold text-white">{title}</p>
        <p className="text-xs text-neutral-400 leading-relaxed">{description}</p>
      </div>
    </div>
  );
};

export default RecommendationCard;
