import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ThreatFeed from "./ThreatFeed";

test("threat feed fills the viewport without a fixed three-column layout", () => {
  const html = renderToStaticMarkup(<ThreatFeed threats={[]} onSelectPacket={() => {}} />);
  expect(html).toContain("grid-cols-[repeat(auto-fit,minmax(400px,1fr))]");
  expect(html).toContain("max-h-[calc(100dvh-15rem)]");
});
