import { useEffect, useState } from "react";
import { api } from "./lib";

export default function useAIEnabled() {
  const [enabled, setEnabled] = useState(false);
  useEffect(() => {
    let active = true;
    api.get("/settings/ai").then(r => { if (active) setEnabled(r.data.enabled); }).catch(() => {});
    const update = e => setEnabled(!!e.detail.aiEnabled);
    window.addEventListener("nscout:preferences", update);
    return () => { active = false; window.removeEventListener("nscout:preferences", update); };
  }, []);
  return enabled;
}
