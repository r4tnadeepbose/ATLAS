import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { ReactNode } from "react";
import { cn } from "@/utils";
import { EmptyState } from "@/components/ui/primitives";

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#F87171",
  high: "#FB923C",
  medium: "#FBBF24",
  low: "#38BDF8",
  info: "#94A3B8",
  unknown: "#64748B",
};

const AXIS = { stroke: "#64748B", fontSize: 10, tickLine: false, axisLine: false };

const tooltipStyle = {
  contentStyle: {
    background: "#111821",
    border: "1px solid #2F4052",
    borderRadius: 6,
    fontSize: 11,
    color: "#E5E7EB",
    boxShadow: "0 8px 24px rgba(0,0,0,0.45)",
  },
  labelStyle: { color: "#8995A5", fontSize: 10, marginBottom: 2 },
  itemStyle: { fontSize: 11 },
};

export function ChartFrame({ title, action, children, height = 220, description, className }: { title: string; action?: ReactNode; children: ReactNode; height?: number; description?: string; className?: string }) {
  return (
    <div className={cn("panel flex flex-col", className)}>
      <div className="flex items-start justify-between gap-2 px-3.5 py-2.5">
        <div>
          <p className="text-xs font-semibold text-ink">{title}</p>
          {description ? <p className="text-[10px] text-muted">{description}</p> : null}
        </div>
        {action}
      </div>
      <div className="px-1 pb-2" style={{ height }}>
        {children}
      </div>
    </div>
  );
}

export function SeverityDonut({ data, height = 220 }: { data: { severity?: string; name?: string; count?: number; value?: number }[]; height?: number }) {
  const total = data.reduce((sum, item) => sum + (item.count ?? item.value ?? 0), 0);
  if (!total) return <EmptyState title="No findings yet" className="py-8" />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          isAnimationActive={false}
          data={data}
          dataKey={(entry: any) => entry.count ?? entry.value ?? 0}
          nameKey={(entry: any) => entry.severity ?? entry.name}
          innerRadius="58%"
          outerRadius="82%"
          paddingAngle={2}
          stroke="#0B0F14"
          strokeWidth={2}
        >
          {data.map((entry) => (
            <Cell key={entry.severity ?? entry.name} fill={SEVERITY_COLORS[entry.severity ?? entry.name ?? "info"] || "#64748B"} />
          ))}
        </Pie>
        <Tooltip {...tooltipStyle} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function SeverityLegend({ data }: { data: { severity?: string; name?: string; count?: number; value?: number }[] }) {
  const total = data.reduce((sum, item) => sum + (item.count ?? item.value ?? 0), 0) || 1;
  return (
    <div className="space-y-1.5">
      {data.map((item) => {
        const key = item.severity ?? item.name ?? "info";
        const value = item.count ?? item.value ?? 0;
        return (
          <div key={key} className="flex items-center gap-2 text-2xs">
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEVERITY_COLORS[key] || "#64748B" }} />
            <span className="flex-1 capitalize text-muted">{key}</span>
            <span className="tabular-nums text-ink">{value}</span>
            <span className="w-9 text-right tabular-nums text-muted">{Math.round((value / total) * 100)}%</span>
          </div>
        );
      })}
    </div>
  );
}

export function TrendArea({
  data,
  dataKey,
  xKey,
  color = "#36D399",
  height = 220,
  yDomain,
  formatter,
}: {
  data: any[];
  dataKey: string;
  xKey: string;
  color?: string;
  height?: number;
  yDomain?: [number, number];
  formatter?: (value: number) => string;
}) {
  if (!data.length) return <EmptyState title="Not enough history" className="py-8" />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 10, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id={`gradient-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.28} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#243140" strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey={xKey} {...AXIS} tickFormatter={(value) => String(value).slice(5)} />
        <YAxis {...AXIS} domain={yDomain} width={42} tickFormatter={formatter} />
        <Tooltip {...tooltipStyle} formatter={(value: any) => [formatter ? formatter(Number(value)) : value, dataKey]} />
        <Area isAnimationActive={false} type="monotone" dataKey={dataKey} stroke={color} strokeWidth={1.5} fill={`url(#gradient-${dataKey})`} dot={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function SeverityStackedBars({ data, xKey = "date", height = 220 }: { data: any[]; xKey?: string; height?: number }) {
  if (!data.length) return <EmptyState title="No discovery history" className="py-8" />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 10, left: -20, bottom: 0 }} barSize={14}>
        <CartesianGrid stroke="#243140" strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey={xKey} {...AXIS} tickFormatter={(value) => String(value).slice(5)} />
        <YAxis {...AXIS} width={34} allowDecimals={false} />
        <Tooltip {...tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 10, color: "#8995A5" }} iconSize={7} />
        {(["critical", "high", "medium", "low", "info"] as const).map((severity) => (
          <Bar isAnimationActive={false} key={severity} dataKey={severity} stackId="a" fill={SEVERITY_COLORS[severity]} radius={[0, 0, 0, 0]} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

export function HorizontalBars({
  data,
  dataKey = "value",
  labelKey = "name",
  color = "#38BDF8",
  height = 220,
  onBarClick,
}: {
  data: any[];
  dataKey?: string;
  labelKey?: string;
  color?: string;
  height?: number;
  onBarClick?: (entry: any) => void;
}) {
  if (!data.length) return <EmptyState title="No data" className="py-8" />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 4, bottom: 0 }} barSize={12}>
        <CartesianGrid stroke="#243140" strokeDasharray="2 4" horizontal={false} />
        <XAxis type="number" {...AXIS} allowDecimals={false} />
        <YAxis type="category" dataKey={labelKey} {...AXIS} width={118} tick={{ fill: "#8995A5", fontSize: 10 }} />
        <Tooltip {...tooltipStyle} cursor={{ fill: "rgba(54,211,153,0.05)" }} />
        <Bar isAnimationActive={false} dataKey={dataKey} fill={color} radius={[0, 3, 3, 0]} onClick={onBarClick}>
          {data.map((entry, index) => (
            <Cell key={index} fill={entry.color || color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function TrendLines({ data, series, xKey = "date", height = 220 }: { data: any[]; series: { key: string; color: string; label: string }[]; xKey?: string; height?: number }) {
  if (data.length < 2) return <EmptyState title="Not enough history yet" description="Trend data appears once at least two periods are recorded." className="py-8" />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 10, left: -20, bottom: 0 }}>
        <CartesianGrid stroke="#243140" strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey={xKey} {...AXIS} />
        <YAxis {...AXIS} width={40} />
        <Tooltip {...tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 10, color: "#8995A5" }} iconSize={7} />
        {series.map((item) => (
          <Line isAnimationActive={false} key={item.key} type="monotone" dataKey={item.key} name={item.label} stroke={item.color} strokeWidth={1.5} dot={false} />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}

export function PostureGauge({ score, height = 180 }: { score: number; height?: number }) {
  const color = score >= 75 ? "#36D399" : score >= 50 ? "#FBBF24" : "#F87171";
  return (
    <div className="relative" style={{ height }}>
      <ResponsiveContainer width="100%" height={height}>
        <RadialBarChart innerRadius="72%" outerRadius="100%" barSize={14} data={[{ value: score, fill: color }]} startAngle={210} endAngle={-30}>
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar isAnimationActive={false} dataKey="value" cornerRadius={8} background={{ fill: "#1A2430" }} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center pt-4">
        <span className="text-3xl font-semibold tabular-nums" style={{ color }}>{score.toFixed(0)}</span>
        <span className="text-[10px] uppercase tracking-[0.14em] text-muted">Posture</span>
      </div>
    </div>
  );
}
