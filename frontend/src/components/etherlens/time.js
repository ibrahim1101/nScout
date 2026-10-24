export function packetDate(timestamp) {
  if (timestamp === null || timestamp === undefined || timestamp === "") return null;
  const value = Number(timestamp);
  if (!Number.isFinite(value)) return null;
  const date = new Date(value * 1000);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatPacketTime(timestamp) {
  const date = packetDate(timestamp);
  if (!date) return "—";
  return date.toLocaleTimeString([], {
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    fractionalSecondDigits: 3, hour12: false,
  });
}

export function formatPacketDateTime(timestamp) {
  const date = packetDate(timestamp);
  return date ? date.toLocaleString() : "—";
}

export function systemTimeZone() {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || "system local time";
}
