import { buildTopologyLayout } from "./TopologyMap";

const hosts = (count) => Array.from({ length: count }, (_, i) => ({
  id: `10.0.${Math.floor(i / 254)}.${(i % 254) + 1}`,
  type: i % 5 === 0 ? "external" : "local",
}));

describe("topology layout geometry", () => {
  test.each(["grouped", "columns", "radial"])("%s places all nodes in finite coordinates", (mode) => {
    const nodes = hosts(180);
    const result = buildTopologyLayout(nodes, { mode });
    expect(Object.keys(result.positions)).toHaveLength(nodes.length);
    for (const node of nodes) {
      const { x, y } = result.positions[node.id];
      expect(Number.isFinite(x) && Number.isFinite(y)).toBe(true);
      expect(x).toBeGreaterThanOrEqual(0);
      expect(x).toBeLessThanOrEqual(result.w);
      expect(y).toBeGreaterThanOrEqual(0);
      expect(y).toBeLessThanOrEqual(result.h);
    }
  });

  test("empty topology returns a valid viewport", () => {
    const result = buildTopologyLayout([]);
    expect(result.positions).toEqual({});
    expect(result.w).toBeGreaterThan(0);
    expect(result.h).toBeGreaterThan(0);
  });

  test("focused layout does not stack neighbors on the same coordinates", () => {
    const nodes = hosts(100);
    const result = buildTopologyLayout(nodes, { focusId: nodes[0].id });
    expect(result.positions[nodes[0].id]).toEqual({ x: result.w / 2, y: result.h / 2 });
    const coords = nodes.map((n) => {
      const p = result.positions[n.id];
      return `${p.x.toFixed(5)}:${p.y.toFixed(5)}`;
    });
    expect(new Set(coords).size).toBe(nodes.length);
  });

  test("flagged nodes remain represented", () => {
    const nodes = hosts(12);
    const flaggedIds = new Set([nodes[2].id, nodes[9].id]);
    const result = buildTopologyLayout(nodes, { flaggedIds });
    expect(result.positions[nodes[2].id]).toBeDefined();
    expect(result.positions[nodes[9].id]).toBeDefined();
  });
});

describe("topology component render smoke tests", () => {
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const TopologyMap = require("./TopologyMap").default;

  test("renders an empty topology without initialization errors", () => {
    expect(() => renderToStaticMarkup(
      React.createElement(TopologyMap, { topology: { nodes: [], edges: [] }, threats: [] })
    )).not.toThrow();
  });

  test("renders a populated topology with security findings", () => {
    const nodes = hosts(24);
    const topology = { nodes, edges: [{ source: nodes[0].id, target: nodes[1].id, bytes: 1024 }] };
    expect(() => renderToStaticMarkup(
      React.createElement(TopologyMap, { topology, threats: [{ src: nodes[0].id, dst: nodes[1].id }] })
    )).not.toThrow();
  });
});
