import React, { useMemo, useState } from "react";
import { humanBytes } from "../format";
import { Icon } from "../icons";

/**
 * 主体文件列表：名称 / 大小 / 压缩后 / 加密。
 * 大部分界面空间都给它 —— 像 7-Zip 一样。
 */
export default function FileList({ view, loading }) {
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    if (!view) return [];
    const q = query.trim().toLowerCase();
    const list = [...view.entries].sort((a, b) => {
      // 目录在前，其余按名称
      if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    return q ? list.filter((e) => e.name.toLowerCase().includes(q)) : list;
  }, [view, query]);

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
        <div className="fl-empty-sub">点击工具栏「打开」或 Ctrl+O 选择文件</div>
      </div>
    );
  }

  return (
    <div className="fl-root">
      <div className="fl-head">
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
        </span>
      </div>

      <div className="fl-scroll">
        {rows.length === 0 ? (
          <div className="fl-status">
            <div className="fl-empty-title">没有匹配的条目</div>
            {view.entries.length === 0 && view.encryption ? (
              <div className="fl-empty-sub">{view.encryption}</div>
            ) : null}
          </div>
        ) : (
          <table className="fl-table">
            <thead>
              <tr>
                <th className="fl-col-name">名称</th>
                <th className="fl-col-size">大小</th>
                <th className="fl-col-packed">压缩后</th>
                <th className="fl-col-enc">加密</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e, i) => (
                <tr key={`${e.name}-${i}`}>
                  <td className="fl-col-name">
                    <span className="fl-name">
                      <Icon
                        name={e.is_dir ? "folder" : "file"}
                        size={14}
                        className={e.is_dir ? "fl-ico folder" : "fl-ico"}
                      />
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
                  <td className="fl-col-enc">
                    {e.encrypted ? (
                      <Icon name="lock" size={12} className="fl-lock" />
                    ) : (
                      <span className="fl-dash">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
