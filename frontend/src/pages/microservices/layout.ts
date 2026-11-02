import { useMemo } from "react";
import type { GraphEdge, GraphNode } from "@/types";

interface PositionedNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

const WIDTH = 1200;
const HEIGHT = 680;

export function layoutGraph(nodes: GraphNode[], edges: GraphEdge[]): Map<string, { x: number; y: number }> {
  const positioned: PositionedNode[] = nodes.map((node, index) => {
    const angle = (index / Math.max(1, nodes.length)) * Math.PI * 2;
    const radius = Math.min(WIDTH, HEIGHT) * 0.32;
    return {
      ...node,
      x: WIDTH / 2 + Math.cos(angle) * radius + (index % 5) * 6,
      y: HEIGHT / 2 + Math.sin(angle) * radius + (index % 7) * 5,
      vx: 0,
      vy: 0,
    };
  });
  const byId = new Map(positioned.map((node) => [node.id, node]));
  const iterations = 260;
  const repulsion = 9000;
  const springLength = 130;

  for (let step = 0; step < iterations; step += 1) {
    for (let i = 0; i < positioned.length; i += 1) {
      const a = positioned[i];
      for (let j = i + 1; j < positioned.length; j += 1) {
        const b = positioned[j];
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        let distance = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = repulsion / (distance * distance);
        dx /= distance;
        dy /= distance;
        a.vx += dx * force;
        a.vy += dy * force;
        b.vx -= dx * force;
        b.vy -= dy * force;
      }
    }
    for (const edge of edges) {
      const source = byId.get(edge.source);
      const target = byId.get(edge.target);
      if (!source || !target) continue;
      let dx = target.x - source.x;
      let dy = target.y - source.y;
      const distance = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (distance - springLength) * 0.012;
      dx /= distance;
      dy /= distance;
      source.vx += dx * force * 18;
      source.vy += dy * force * 18;
      target.vx -= dx * force * 18;
      target.vy -= dy * force * 18;
    }
    for (const node of positioned) {
      node.vx += (WIDTH / 2 - node.x) * 0.0016;
      node.vy += (HEIGHT / 2 - node.y) * 0.0016;
      node.vx *= 0.82;
      node.vy *= 0.82;
      node.x = Math.max(60, Math.min(WIDTH - 60, node.x + node.vx));
      node.y = Math.max(50, Math.min(HEIGHT - 50, node.y + node.vy));
    }
  }

  return new Map(positioned.map((node) => [node.id, { x: node.x, y: node.y }]));
}

export function useGraphLayout(nodes: GraphNode[], edges: GraphEdge[]) {
  return useMemo(() => ({ nodes, edges, positions: layoutGraph(nodes, edges) }), [nodes, edges]);
}

interface LabelPlacement {
  x: number;
  y: number;
  anchor: "middle" | "start" | "end";
  visible: boolean;
}

const overlaps = (a: [number, number, number, number], b: [number, number, number, number]) =>
  a[0] < b[1] && b[0] < a[1] && a[2] < b[3] && b[2] < a[3];

export function placeLabels(nodes: GraphNode[], positions: Map<string, { x: number; y: number }>): Map<string, LabelPlacement> {
  const placed: [number, number, number, number][] = [];
  const result = new Map<string, LabelPlacement>();
  const ordered = [...nodes].sort(
    (a, b) => (b.open_findings || 0) - (a.open_findings || 0) || (b.risk_score || 0) - (a.risk_score || 0),
  );

  for (const node of ordered) {
    const position = positions.get(node.id);
    if (!position) continue;
    const text = node.label.length > 24 ? `${node.label.slice(0, 23)}…` : node.label;
    const width = Math.min(190, text.length * 6.1 + 6);
    const candidates: LabelPlacement[] = [
      { x: position.x, y: position.y - 14, anchor: "middle", visible: true },
      { x: position.x, y: position.y + 19, anchor: "middle", visible: true },
      { x: position.x + 12, y: position.y + 4, anchor: "start", visible: true },
      { x: position.x - 12, y: position.y + 4, anchor: "end", visible: true },
    ];

    let chosen: LabelPlacement | null = null;
    for (const candidate of candidates) {
      const left = candidate.anchor === "middle" ? candidate.x - width / 2 : candidate.anchor === "start" ? candidate.x : candidate.x - width;
      const rect: [number, number, number, number] = [left, left + width, candidate.y - 10, candidate.y + 4];
      if (rect[0] < 8 || rect[1] > WIDTH - 8 || rect[2] < 8 || rect[3] > HEIGHT - 8) continue;
      const hitsLabel = placed.some((other) => overlaps(rect, other));
      // Keep labels off other nodes so click targets stay readable.
      const hitsNode = nodes.some((other) => {
        if (other.id === node.id) return false;
        const otherPosition = positions.get(other.id);
        if (!otherPosition) return false;
        return otherPosition.x > rect[0] - 6 && otherPosition.x < rect[1] + 6 && otherPosition.y > rect[2] - 4 && otherPosition.y < rect[3] + 6;
      });
      if (!hitsLabel && !hitsNode) {
        chosen = candidate;
        placed.push(rect);
        break;
      }
    }

    result.set(node.id, chosen || { x: position.x, y: position.y - 14, anchor: "middle", visible: false });
  }
  return result;
}
