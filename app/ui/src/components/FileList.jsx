import React, { useMemo, useState } from "react";
import { humanBytes } from "../format";
import { Icon } from "../icons";

const MONTHS = ["01","02","03","04","05","06","07","08","09","10","11","12"];

function fmtTime(unix) {
  if (!unix) return "—";
  const d = new Date(unix * 1000);
  return `${d.getFullYear()}-${MONTHS[d.getMonth()]}-${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

/** 按扩展名选图标和色调。 */
function fileKind(name) {
  const ext = name.includes(".") ? name.split(".").pop().toLowerCase() : "";
  if (["zip","7z","rar","tar","gz","xz","bz2","tgz"].includes(ext)) return { icon: "archive", cls: "fl-k-arch" };
  if (["txt","md","log","csv"].includes(ext)) return { icon: "file", cls: "fl-k-txt" };
  if (["png","jpg","jpeg","gif","webp","svg","bmp"].includes(ext)) return { icon: "file", cls: "fl-k-img" };
  if (["mp3","wav","flac","ogg"].includes(ext)) return { icon: "file", cls: "fl-k-audio" };
  if (["mp4","mkv","avi","webm","mov"].includes(ext)) return { icon: "file", cls: "fl-k-vid" };
  if (["exe","dll","so","bin","apk"].includes(ext)) return { icon: "file", cls: "fl-k-bin" };
  return { icon: "file", cls: "" };
}

/**
 * 主体文件列表：名称 / 大小 / 压缩后 / 修改时间 / 加密。
 * 支持多选（Ctrl/Shift + 点击）、双击目录进入、面包屑返回。
 */
export default function FileList({ view, loading, selected, onSelected, onUnlockHeader }) {
  const [query, setQuery] = useState("");
  const [cwd, setCwd] = useState(""); // 当前子目录（'' = 根）
  const [lastIndex, setLastIndex] = useState(-1);

  // 目录树视图: entries → 当前目录的直接子项
  const { rows, breadcrumbs } = useMemo(() => {
    if (!view) return { rows: [], breadcrumbs: [] };
    const q = query.trim().toLowerCase();
    const prefix = cwd ? cwd.replace(/\/$/, "") + "/" : "";
    const seen = new Map(); // name → row (目录折叠)
    for (const e of view.entries) {
      const full = e.name.replace(/\/$/, "");
      if (prefix && !full.startsWith(prefix)) continue;
      const rest = full.slice(prefix.length);
      if (!rest) continue; // 自身
      const slash = rest.indexOf("/");
      const isChildDir = slash >= 0;
      const name = isChildDir ? rest.slice(0, slash) : rest;
      if (isChildDir) {
        const prev = seen.get(name);
        if (!prev) {
          seen.set(name, { name, is_dir: true, encrypted: false, compressed_size: 0, uncompressed_size: 0, mtime: 0, __virtual: true });
        } else if (e.mtime && (!prev.mtime || e.mtime > prev.mtime)) {
          prev.mtime = e.mtime;
        }
        continue;
      }
      if (q && !name.toLowerCase().includes(q)) continue;
      seen.set(name, { ...e, name });
    }
    const list = [...seen.values()].sort((a, b) => {
      if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
      return a.name.localeCompare(b.name, "zh");
    });
    // 搜索时全局搜索（忽略 cwd）
    let out = list;
    if (q && cwd) {
      const all = view.entries
        .filter((e) => e.name.toLowerCase().includes(q))
        .map((e) => ({ ...e, name: e.name.replace(/\/$/, "") }))
        .sort((a, b) => (a.is_dir === b.is_dir ? a.name.localeCompare(b.name, "zh") : a.is_dir ? -1 : 1));
      out = all;
    }
    const crumbs = cwd ? cwd.replace(/\/$/, "").split("/") : [];
    return { rows: out, breadcrumbs: crumbs };
  }, [view, query, cwd]);

  const totals = useMemo(
    () =>
      rows.reduce(
        (acc, e) => {
          if (!e.is_dir) {
            acc.n += 1;
            acc.size += e.uncompressed_size;
            acc.packed += e.compressed_size;
          }
          return acc;
        },
        { n: 0, size: 0, packed: 0 }
      ),
    [rows]
  );

  const toggle = (name, e, i) => {
    const isSel = selected.has(name);
    let next = new Set(selected);
    if (e && (e.ctrlKey || e.metaKey)) {
      if (isSel) next.delete(name); else next.add(name);
    } else if (e && e.shiftKey && lastIndex >= 0) {
      const [a, b] = [Math.min(lastIndex, i), Math.max(lastIndex, i)];
      next = new Set(rows.slice(a, b + 1).map((r) => r.name));
    } else {
      next = isSel && selected.size === 1 ? new Set() : new Set([name]);
    }
    setLastIndex(i);
    onSelected(next);
  };

  const openRow = (row) => {
    if (row.is_dir) {
      const next = cwd ? `${cwd.replace(/\/$/, "")}/${row.name}` : row.name;
      setCwd(next);
      onSelected(new Set());
      setQuery("");
    }
  };

  if (loading) {
    return (
      <div className="fl-status">
        <span className="spinner" /> 读取中…
      </div>
    );
  }

  if (!view) {
    return (
      <div className="fl-status">
        <div className="fl-empty-icon">
          <Icon name="archive" size={22} />
        </div>
        <div className="fl-empty-title">未打开归档</div>
        <div className="fl-empty-sub">点击工具栏「打开」、Ctrl+O，或直接拖入归档文件</div>
      </div>
    );
  }

  // 加密头 7z：条目列表为空（需要密码解锁）
  if (view.entries.length === 0 && view.encryption) {
    return (
      <div className="fl-status">
        <div className="fl-empty-icon">
          <Icon name="lock" size={22} />
        </div>
        <div className="fl-empty-title">归档头部已加密</div>
        <div className="fl-empty-sub">{view.encryption}</div>
        {onUnlockHeader && (
          <form
            className="unlock-row"
            onSubmit={(e) => {
              e.preventDefault();
              const pw = e.target.pw.value;
              if (pw) onUnlockHeader(pw);
            }}
          >
            <input className="input" name="pw" type="password" placeholder="输入密码解锁列表…" autoFocus autoComplete="off" />
            <button className="btn btn-primary btn-sm" type="submit">解锁</button>
          </form>
        )}
      </div>
    );
  }

  return (
    <div className="fl-root">
      <div className="fl-head">
        {cwd ? (
          <div className="fl-crumbs">
            <button className="crumb" onClick={() => { setCwd(""); onSelected(new Set()); }}>
              <Icon name="archive" size={12} />
            </button>
            {breadcrumbs.map((c, i) => (
              <React.Fragment key={i}>
                <span className="crumb-sep">/</span>
                <button
                  className="crumb"
                  onClick={() => {
                    setCwd(breadcrumbs.slice(0, i + 1).join("/"));
                    onSelected(new Set());
                  }}
                >
                  {c}
                </button>
              </React.Fragment>
            ))}
          </div>
        ) : (
          <span className="fl-cwd-hint">
            <Icon name="archive" size={12} /> 根目录
          </span>
        )}
        <input
          className="fl-search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="筛选名称…"
          spellCheck={false}
        />
        <span className="fl-count">
          {totals.n} 个文件 · {humanBytes(totals.size)}
          {totals.packed > 0 ? ` (压缩后 ${humanBytes(totals.packed)})` : ""}
          {selected.size > 0 ? ` · 已选 ${selected.size} 项` : ""}
        </span>
      </div>

      <div className="fl-scroll">
        {rows.length === 0 ? (
          <div className="fl-status">
            <div className="fl-empty-title">没有匹配的条目</div>
            {query && <div className="fl-empty-sub">清除筛选试试</div>}
          </div>
        ) : (
          <table className="fl-table">
            <thead>
              <tr>
                <th className="fl-col-name">名称</th>
                <th className="fl-col-size">大小</th>
                <th className="fl-col-packed">压缩后</th>
                <th className="fl-col-time">修改时间</th>
                <th className="fl-col-enc">加密</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e, i) => {
                const kind = e.is_dir ? { icon: "folder", cls: "fl-ico folder" } : fileKind(e.name);
                const isSel = selected.has(e.name);
                return (
                  <tr
                    key={`${e.name}-${i}`}
                    className={isSel ? "fl-selected" : ""}
                    onClick={(ev) => toggle(e.name, ev, i)}
                    onDoubleClick={() => openRow(e)}
                  >
                    <td className="fl-col-name">
                      <span className="fl-name">
                        <Icon name={e.is_dir ? "folder" : kind.icon} size={14} className={`fl-ico ${e.is_dir ? "folder" : kind.cls}`} />
                        <span className={e.is_dir ? "fl-dirname" : ""}>
                          {e.name}
                          {e.is_dir ? "/" : ""}
                        </span>
                      </span>
                    </td>
                    <td className="fl-col-size fl-num">
                      {e.is_dir ? "—" : humanBytes(e.uncompressed_size)}
                    </td>
                    <td className="fl-col-packed fl-num">
                      {e.is_dir || !e.compressed_size ? "—" : humanBytes(e.compressed_size)}
                    </td>
                    <td className="fl-col-time fl-num">{fmtTime(e.mtime)}</td>
                    <td className="fl-col-enc">
                      {e.encrypted ? (
                        <Icon name="lock" size={12} className="fl-lock" />
                      ) : (
                        <span className="fl-dash">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
