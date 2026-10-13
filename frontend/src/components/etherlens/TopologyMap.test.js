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

  test("exposes keyboard-focusable host controls with accessible labels", () => {
    const nodes = hosts(3);
    const markup = renderToStaticMarkup(
      React.createElement(TopologyMap, { topology: { nodes, edges: [] }, threats: [] })
    );
    expect(markup).toContain('role="button"');
    expect(markup).toContain('tabindex="0"');
    expect(markup).toContain(`Inspect host ${nodes[0].id}`);
    expect(markup).toContain('aria-pressed="false"');
    expect(markup).toContain('Interactive network topology');
    expect(markup).toContain("Tab to a host");
    expect(markup).toContain("Home and End");
    expect(markup).toContain("Escape to clear selection");
  });

  test("renders host navigation targets in visible host order", () => {
    const nodes = hosts(4);
    const markup = renderToStaticMarkup(
      React.createElement(TopologyMap, { topology: { nodes, edges: [] }, threats: [] })
    );
    const targets = [...markup.matchAll(/data-topology-host="([^"]+)"/g)].map((match) => match[1]);
    expect(targets).toEqual(nodes.map((node) => node.id));
    expect((markup.match(/tabindex="0"/g) || []).length).toBeGreaterThanOrEqual(nodes.length);
  });

  test("renders a populated topology with security findings", () => {
    const nodes = hosts(24);
    const topology = { nodes, edges: [{ source: nodes[0].id, target: nodes[1].id, bytes: 1024 }] };
    expect(() => renderToStaticMarkup(
      React.createElement(TopologyMap, { topology, threats: [{ src: nodes[0].id, dst: nodes[1].id }] })
    )).not.toThrow();
  });
});

describe("topology keyboard interactions", () => {
  const React = require("react");
  const { createRoot } = require("react-dom/client");
  const { act } = require("react");

  test("arrow keys move host focus and Enter selects the focused host", async () => {
    const container = document.createElement("div");
    document.body.appendChild(container);
    const root = createRoot(container);
    const nodes = hosts(3);
    try {
      await act(async () => {
        root.render(React.createElement(require("./TopologyMap").default, {
          topology: { nodes, edges: [] }, threats: [],
        }));
      });
      const targets = [...container.querySelectorAll("[data-topology-host]")];
      expect(targets).toHaveLength(3);
      targets[0].focus();
      expect(document.activeElement).toBe(targets[0]);
      await act(async () => {
        targets[0].dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true, cancelable: true }));
      });
      expect(document.activeElement).toBe(targets[1]);
      await act(async () => {
        targets[1].dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
      });
      expect(targets[1].getAttribute("aria-pressed")).toBe("true");
      await act(async () => {
        targets[1].dispatchEvent(new KeyboardEvent("keydown", { key: "End", bubbles: true, cancelable: true }));
      });
      expect(document.activeElement).toBe(targets[2]);
      await act(async () => {
        targets[2].dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true, cancelable: true }));
      });
      expect(document.activeElement).toBe(targets[0]);
      await act(async () => {
        targets[0].dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowLeft", bubbles: true, cancelable: true }));
      });
      expect(document.activeElement).toBe(targets[2]);
      await act(async () => {
        targets[2].dispatchEvent(new KeyboardEvent("keydown", { key: "Home", bubbles: true, cancelable: true }));
      });
      expect(document.activeElement).toBe(targets[0]);
      await act(async () => {
        targets[0].dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true, cancelable: true }));
      });
      expect(targets[0].getAttribute("aria-pressed")).toBe("true");
      await act(async () => {
        targets[0].dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
      });
      expect(targets[0].getAttribute("aria-pressed")).toBe("false");
    } finally {
      await act(async () => root.unmount());
      container.remove();
    }
  });
});
