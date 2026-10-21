export function humanBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let value = n;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return i === 0 ? `${Math.round(value)} B` : `${value.toFixed(value >= 100 ? 0 : 1)} ${units[i]}`;
}

export function humanCount(n) {
  const v = Math.max(0, Number(n) || 0);
  if (v >= 1e12) return `${(v / 1e12).toFixed(2)}T`;
  if (v >= 1e9) return `${(v / 1e9).toFixed(2)}G`;
  if (v >= 1e6) return `${(v / 1e6).toFixed(2)}M`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)}K`;
  return String(Math.round(v));
}

export function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 60) return seconds < 10 ? `${seconds.toFixed(1)}s` : `${Math.round(seconds)}s`;
  const total = Math.round(seconds);
  const m = Math.floor(total / 60);
  const s = total % 60;
  if (m < 60) return `${m} 分 ${String(s).padStart(2, "0")} 秒`;
  const h = Math.floor(m / 60);
  return `${h} 时 ${String(m % 60).padStart(2, "0")} 分`;
}

export function splitPath(path) {
  const norm = String(path || "").replace(/\\/g, "/");
  const i = norm.lastIndexOf("/");
  if (i < 0) return { base: norm, dir: "" };
  if (i === 0) return { base: norm.slice(1), dir: "/" };
  return { base: norm.slice(i + 1), dir: norm.slice(0, i) };
}

export function defaultExtractDir(path) {
  return String(path || "").replace(/\.(zip|7z|tar|gz|tgz|xz|bz2)$/i, "") + "_extracted";
}

export function percentText(pct) {
  if (pct === null || pct === undefined || !Number.isFinite(pct)) return "—";
  if (pct <= 0) return "0%";
  if (pct < 0.001) return "<0.001%";
  if (pct < 1) return `${pct.toFixed(3)}%`;
  if (pct < 10) return `${pct.toFixed(2)}%`;
  return `${pct.toFixed(1)}%`;
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // WebViews without clipboard permission: fall back to execCommand.
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}
