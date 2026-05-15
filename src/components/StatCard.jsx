import React from "react";

const StatCard = ({ icon: Icon, title, value, description, accent = false, colorClass = "" }) => {
  return (
    <div
      className={`rounded-xl border p-5 flex flex-col gap-3 transition-colors
        ${accent
          ? "bg-accent/5 border-accent/20 hover:border-accent/40"
          : "bg-[#222222] border-[#333333] hover:border-[#444444]"
        }`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono uppercase tracking-widest text-neutral-500">{title}</span>
        {Icon && (
          <div className={`p-1.5 rounded-lg ${accent ? "bg-accent/10" : "bg-neutral-800"}`}>
            <Icon size={16} className={colorClass || (accent ? "text-accent" : "text-neutral-400")} />
          </div>
        )}
      </div>
      <div className={`text-3xl font-bold font-mono ${colorClass || (accent ? "text-accent" : "text-white")}`}>
        {value}
      </div>
      {description && (
        <p className="text-xs text-neutral-500">{description}</p>
      )}
    </div>
  );
};

export default StatCard;
