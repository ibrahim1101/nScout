import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import FlowDrawer from "./FlowDrawer";
import GlobalSearchDrawer from "./GlobalSearchDrawer";
import SessionsDrawer from "./SessionsDrawer";
import SettingsDrawer from "./SettingsDrawer";

describe("responsive workspace overlays", () => {
  test("follow-flow dialog expands within the viewport without losing its scroll region", () => {
    const html = renderToStaticMarkup(
      <FlowDrawer open onClose={() => {}} flow={null} />
    );
    expect(html).toContain('data-testid="follow-flow-drawer"');
    expect(html).toContain("max-w-[1600px]");
    expect(html).toContain("h-[min(90dvh,1200px)]");
    expect(html).toContain("overflow-auto");
  });

  test("global search scales with viewport height and width", () => {
    const html = renderToStaticMarkup(
      <GlobalSearchDrawer open onClose={() => {}} />
    );
    expect(html).toContain('aria-label="Global investigation search"');
    expect(html).toContain("max-w-[1280px]");
    expect(html).toContain("max-h-[calc(100dvh-1.5rem)]");
    expect(html).toContain("max-h-[calc(100dvh-12rem)]");
  });

  test("side drawers fill narrow windows and grow on wider displays", () => {
    const sessions = renderToStaticMarkup(
      <SessionsDrawer open onClose={() => {}} />
    );
    const settings = renderToStaticMarkup(
      <SettingsDrawer open onClose={() => {}} />
    );
    expect(sessions).toContain('data-testid="sessions-drawer"');
    expect(sessions).toContain("sm:w-[min(70vw,860px)]");
    expect(settings).toContain('data-testid="settings-drawer"');
    expect(settings).toContain("sm:w-[min(82vw,960px)]");
    expect(settings).toContain("h-[100dvh]");
  });
});
