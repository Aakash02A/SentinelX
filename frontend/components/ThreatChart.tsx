"use client";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

// Mock 24h event data — replace with API fetch
const DATA = [
  { time: "00:00", events: 1200, alerts: 2 },
  { time: "02:00", events: 800,  alerts: 1 },
  { time: "04:00", events: 600,  alerts: 0 },
  { time: "06:00", events: 900,  alerts: 3 },
  { time: "08:00", events: 2100, alerts: 5 },
  { time: "10:00", events: 3400, alerts: 8 },
  { time: "12:00", events: 2900, alerts: 4 },
  { time: "14:00", events: 3200, alerts: 6 },
  { time: "16:00", events: 2840, alerts: 12 },
  { time: "18:00", events: 2100, alerts: 7 },
  { time: "20:00", events: 1600, alerts: 3 },
  { time: "22:00", events: 1300, alerts: 2 },
];

interface TooltipPayloadItem {
  value: number | string;
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: TooltipPayloadItem[];
  label?: string;
}

const CustomTooltip = ({ active, payload, label }: CustomTooltipProps) => {
  if (active && payload && payload.length) {
    return (
      <div className="glass-card p-3 text-xs space-y-1 shadow-xl">
        <p className="text-[var(--color-text-muted)] font-medium">{label}</p>
        <p className="text-blue-400">Events: {payload[0]?.value?.toLocaleString()}</p>
        <p className="text-orange-400">Alerts: {payload[1]?.value}</p>
      </div>
    );
  }
  return null;
};

export default function ThreatChart() {
  return (
    <ResponsiveContainer width="100%" height={180}>
      <AreaChart data={DATA} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="eventsGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25} />
            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="alertsGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.06)" />
        <XAxis
          dataKey="time"
          tick={{ fontSize: 10, fill: "#475569" }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis tick={{ fontSize: 10, fill: "#475569" }} axisLine={false} tickLine={false} />
        <Tooltip content={<CustomTooltip />} />
        <Area
          type="monotone"
          dataKey="events"
          stroke="#3b82f6"
          strokeWidth={2}
          fill="url(#eventsGrad)"
          dot={false}
          activeDot={{ r: 4, fill: "#3b82f6" }}
        />
        <Area
          type="monotone"
          dataKey="alerts"
          stroke="#f97316"
          strokeWidth={2}
          fill="url(#alertsGrad)"
          dot={false}
          activeDot={{ r: 4, fill: "#f97316" }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
