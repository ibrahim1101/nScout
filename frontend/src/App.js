import { useEffect, useState, useRef, useCallback } from "react";
import "@/App.css";
import Dashboard from "@/components/etherlens/Dashboard";

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem("etherlens-theme") || "light");

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "dark") root.classList.add("dark");
    else root.classList.remove("dark");
    localStorage.setItem("etherlens-theme", theme);
  }, [theme]);

  return (
    <div className="App min-h-screen bg-slate-50 dark:bg-[#090D16] text-slate-900 dark:text-slate-100">
      <Dashboard theme={theme} setTheme={setTheme} />
    </div>
  );
}
