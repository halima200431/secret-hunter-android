import React from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { RISK_CHART_COLORS } from "../utils/riskUtils";

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[#2a2a2a] border border-[#404040] rounded-lg px-3 py-2 text-sm">
        <span className="font-medium text-white">{payload[0].name}</span>
        <span className="ml-2 font-mono text-neutral-400">{payload[0].value} détections</span>
      </div>
    );
  }
  return null;
};

const CustomLegend = ({ payload }) => (
  <div className="flex flex-wrap gap-3 justify-center mt-2">
    {payload.map((entry) => (
      <div key={entry.value} className="flex items-center gap-1.5 text-xs text-neutral-400">
        <span className="w-2.5 h-2.5 rounded-sm inline-block" style={{ background: entry.color }} />
        {entry.value}
      </div>
    ))}
  </div>
);

const SeverityChart = ({ data }) => {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="45%"
          innerRadius={55}
          outerRadius={85}
          paddingAngle={3}
          dataKey="value"
        >
          {data.map((entry) => (
            <Cell
              key={entry.name}
              fill={RISK_CHART_COLORS[entry.name] || "#6b7280"}
              stroke="transparent"
            />
          ))}
        </Pie>
        <Tooltip content={<CustomTooltip />} />
        <Legend content={<CustomLegend />} />
      </PieChart>
    </ResponsiveContainer>
  );
};

export default SeverityChart;
