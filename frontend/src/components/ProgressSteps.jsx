import React from "react";
import { CheckCircle, Loader, Circle, XCircle } from "lucide-react";

const STATUS_CONFIG = {
  pending: {
    icon: Circle,
    color: "text-neutral-600",
    bg: "bg-neutral-800",
    label: "En attente",
  },
  running: {
    icon: Loader,
    color: "text-accent",
    bg: "bg-accent/10",
    label: "En cours",
    spin: true,
  },
  completed: {
    icon: CheckCircle,
    color: "text-risk-low",
    bg: "bg-risk-low/10",
    label: "Terminé",
  },
  failed: {
    icon: XCircle,
    color: "text-risk-critical",
    bg: "bg-risk-critical/10",
    label: "Échec",
  },
};

const ProgressSteps = ({ steps }) => {
  return (
    <div className="flex flex-col gap-1">
      {steps.map((step, idx) => {
        const config = STATUS_CONFIG[step.status] || STATUS_CONFIG.pending;
        const Icon = config.icon;
        const isLast = idx === steps.length - 1;

        return (
          <div key={step.id} className="flex gap-4">
            {/* Connector line */}
            <div className="flex flex-col items-center">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${config.bg}`}>
                <Icon
                  size={16}
                  className={`${config.color} ${config.spin ? "animate-spin" : ""}`}
                />
              </div>
              {!isLast && (
                <div
                  className={`w-px flex-1 my-1 ${
                    step.status === "completed" ? "bg-risk-low/30" : "bg-[#2e2e2e]"
                  }`}
                  style={{ minHeight: "16px" }}
                />
              )}
            </div>

            {/* Content */}
            <div className="pb-4 flex-1 min-w-0">
              <div className="flex items-center gap-2 mt-1.5">
                <span
                  className={`text-sm font-medium ${
                    step.status === "completed"
                      ? "text-white"
                      : step.status === "running"
                      ? "text-white"
                      : "text-neutral-500"
                  }`}
                >
                  {step.label}
                </span>
                {step.status === "running" && (
                  <span className="text-xs font-mono text-accent animate-pulse">
                    {step.detail || "Traitement..."}
                  </span>
                )}
                {step.status === "completed" && step.detail && (
                  <span className="text-xs font-mono text-neutral-500">{step.detail}</span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default ProgressSteps;
