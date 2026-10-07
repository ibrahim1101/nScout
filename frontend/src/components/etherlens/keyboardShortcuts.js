export const KEYBOARD_SHORTCUTS = [
  { id: "focus-filter", category: "Search", keys: ["Ctrl / ⌘", "K"], description: "Focus the packet filter", key: "k", primary: true, allowInForm: true },
  { id: "open-settings", category: "Navigation", keys: ["Ctrl / ⌘", ","], description: "Open Settings", key: ",", primary: true, allowInForm: true },
  { id: "open-sessions", category: "Capture", keys: ["Ctrl / ⌘", "Shift", "S"], description: "Open Capture Sessions", key: "s", primary: true, shift: true, allowInForm: true },
  { id: "toggle-capture", category: "Capture", keys: ["Space"], description: "Start or stop capture", code: "Space" },
  { id: "close-panels", category: "Navigation", keys: ["Esc"], description: "Close the active drawer or panel", key: "Escape", allowInForm: true },
  { id: "shortcut-help", category: "Navigation", keys: ["?"], description: "Open this keyboard-shortcut reference", key: "?", ignoreShift: true },
  ...["Packets", "Intelligence", "Live Hosts", "Investigations", "PCAP Investigation", "Analytics", "Flows", "Topology", "Threats"].map((label, index) => ({
    id: `tab-${index + 1}`,
    category: "Navigation",
    keys: ["Alt", String(index + 1)],
    description: `Open ${label}`,
    code: `Digit${index + 1}`,
    alt: true,
    tabIndex: index,
  })),
];

export function shortcutMatches(event, shortcut) {
  if (shortcut.code ? event.code !== shortcut.code : event.key.toLowerCase() !== shortcut.key.toLowerCase()) return false;
  if (!!shortcut.primary !== !!(event.ctrlKey || event.metaKey)) return false;
  if (!!shortcut.alt !== !!event.altKey) return false;
  if (!shortcut.ignoreShift && !!shortcut.shift !== !!event.shiftKey) return false;
  return true;
}

export function isInteractiveTarget(target) {
  return !!target?.closest?.("input, textarea, select, button, a, [contenteditable='true'], [role='textbox']");
}
