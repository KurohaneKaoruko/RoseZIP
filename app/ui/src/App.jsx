import React, { useCallback, useEffect, useState } from "react";
import { invoke, pickArchive, pickDirectory, pickFiles, pickZipSave, getCurrentWebview } from "./api";
import { defaultExtractDir } from "./format";
import { RoseMark } from "./icons";
import { ToastProvider, useToast } from "./ui";
import Toolbar, { AddressBar } from "./components/Toolbar";
import FileList from "./components/FileList";
import { BenchDialog, CompressDialog, CrackDialog, ExtractDialog, Modal } from "./components/Dialogs";
import { Button } from "./ui";

const ARCHIVE_RE = /\.(zip|7z|tar|gz|tgz|xz|bz2)$/i;

/** In-place entry rename dialog. */
function RenameDialog({ path, oldName, password, onClose, onDone }) {
  const [name, setName] = useState(oldName);
  const [busy, setBusy] = useState(false);
  const inputRef = React.useRef(null);
  useEffect(() => {
    inputRef.current?.focus();
    // preselect the basename (before the last slash)
    const idx = oldName.lastIndexOf("/");
    inputRef.current?.setSelectionRange(idx + 1, oldName.length);
  }, [oldName]);

  async function run() {
    if (!name.trim() || name.trim() === oldName) return onClose();
    setBusy(true);
    try {
      const r = await invoke("rename_entry_cmd", {
        path,
        oldName,
        newName: name.trim(),
        password: password || null,
      });
      onDone(r);
    } catch (e) {
      onDone({ ok: false, message: String(e) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="重命名条目"
      icon="file"
      onClose={busy ? undefined : onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>取消</Button>
          <Button icon="check" onClick={run} loading={busy} disabled={!name.trim()}>确定</Button>
        </>
      }
    >
      <div className="form-rows">
        <div className="frow">
          <span className="frow-label">新名称</span>
          <input
            ref={inputRef}
            className="input frow-main mono"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            spellCheck={false}
            disabled={busy}
          />
        </div>
      </div>
    </Modal>
  );
}

/** Row context menu: extract / rename / delete. */
function RowContextMenu({ x, y, entry, multi, onClose, onAction }) {
  const ref = React.useRef(null);
  useEffect(() => {
    const close = () => onClose();
    window.addEventListener("click", close);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("blur", close);
    };
  }, [onClose]);
  const item = (label, action, opts = {}) => (
    <button
      className="ctx-item"
      disabled={opts.disabled}
      onClick={() => { onClose(); onAction(action, entry); }}
    >
      {label}
    </button>
  );
  return (
    <div className="ctx-menu" style={{ left: x, top: y }} ref={ref} onClick={(e) => e.stopPropagation()}>
      {item(multi ? `解压所选 ${multi} 项` : "解压此条目", "extract")}
      {item("复制路径", "copyPath")}
      <div className="ctx-sep" />
      {item("重命名…", "rename", { disabled: multi > 1 })}
      {item(multi ? `删除所选 ${multi} 项` : "删除", "delete")}
    </div>
  );
}

function Shell() {
  const notify = useToast();
  const [path, setPath] = useState("");
  const [view, setView] = useState(null);
  const [loading, setLoading] = useState(false);
  const [dialog, setDialog] = useState(null); // null | 'extract' | 'compress' | 'bench' | 'crack'
  const [version, setVersion] = useState("");
  const [selected, setSelected] = useState(() => new Set());
  const [dragOver, setDragOver] = useState(false);
  const [testing, setTesting] = useState(false);
  // 7z 头加密：解锁时暂存的密码（随后的解压/测试复用）
  const [headerPw, setHeaderPw] = useState(null);
  const [extractNames, setExtractNames] = useState(null); // null = 全部
  const [ctxMenu, setCtxMenu] = useState(null); // {x, y, entry}
  const [renameTarget, setRenameTarget] = useState(null); // entry name

  useEffect(() => {
    invoke("app_version").then(setVersion).catch(() => {});
  }, []);

  const load = useCallback(
    async (p, pw = null) => {
      if (!p) return;
      setLoading(true);
      setHeaderPw(pw);
      setSelected(new Set());
      try {
        const v = await invoke("inspect_archive", { path: p, password: pw });
        setPath(v.path || p);
        setView(v);
      } catch (e) {
        notify("error", `无法读取：${e}`);
        setView(null);
      } finally {
        setLoading(false);
      }
    },
    [notify]
  );

  const open = useCallback(async () => {
    const picked = await pickArchive();
    if (picked) load(picked);
  }, [load]);

  // Ctrl+O 打开
  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "o") {
        e.preventDefault();
        open();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  // 启动参数直接打开归档（双击关联 / CLI 传参）
  useEffect(() => {
    invoke("startup_path").then((p) => {
      if (p) load(p);
    }).catch(() => {});
  }, [load]);

  // 拖拽打开归档（Tauri 原生事件：HTML5 drop 拿不到绝对路径）
  useEffect(() => {
    let unlisten;
    getCurrentWebview()
      .onDragDropEvent((ev) => {
        if (ev.payload.type === "enter" || ev.payload.type === "over") {
          setDragOver(true);
        } else if (ev.payload.type === "leave") {
          setDragOver(false);
        } else if (ev.payload.type === "drop") {
          setDragOver(false);
          const p = ev.payload.paths?.[0];
          if (!p) return;
          if (ARCHIVE_RE.test(p)) {
            load(p);
          } else {
            notify("info", "不支持的文件类型（支持 zip/7z/tar/gz/xz/bz2）");
          }
        }
      })
      .then((u) => (unlisten = u))
      .catch(() => {});
    return () => unlisten?.();
  }, [load, notify]);

  // 测试归档完整性
  const runTest = useCallback(async () => {
    if (!path) return;
    setTesting(true);
    try {
      const r = await invoke("test_archive_cmd", { path, password: headerPw });
      if (r.ok) notify("success", r.message);
      else notify("error", r.errors?.[0] || r.message);
    } catch (e) {
      notify("error", String(e));
    } finally {
      setTesting(false);
    }
  }, [path, headerPw, notify]);

  const hasArchive = Boolean(view) || loading;
  const selectedNames = selected.size > 0 ? [...selected] : null;

  /** Context-menu actions on rows (extract/rename/delete/copyPath). */
  const handleContextAction = useCallback(
    async (action, entry) => {
      if (!view) return;
      const names = selected.size > 1 ? [...selected] : [entry.name];
      if (action === "extract") {
        setExtractNames(names);
        setDialog("extract");
      } else if (action === "copyPath") {
        try {
          await navigator.clipboard.writeText(`${path}::${entry.name}`);
          notify("success", "已复制路径");
        } catch {
          notify("error", "复制失败");
        }
      } else if (action === "rename") {
        setRenameTarget(entry.name);
      } else if (action === "delete") {
        const label = names.length === 1 ? entry.name : `${names.length} 个条目`;
        if (!window.confirm(`从压缩包中删除 ${label}？此操作直接改写文件。`)) return;
        try {
          const r = await invoke("delete_entries_cmd", {
            path,
            entries: names,
            password: headerPw || null,
          });
          notify(r.ok ? "success" : "error", r.message);
          if (r.ok) load(path, headerPw);
        } catch (e) {
          notify("error", `删除失败：${e}`);
        }
      }
    },
    [view, selected, path, headerPw, load, notify]
  );

  return (
    <div className={`app-shell ${dragOver ? "drag-over" : ""}`}>
      {dragOver && (
        <div className="drag-overlay">
          <div className="drag-card">
            <RoseMark size={34} />
            <span>松开以打开归档</span>
          </div>
        </div>
      )}

      <header className="top">
        <div className="brand-mini">
          <RoseMark size={20} />
          <span className="brand-mini-name">RoseZIP</span>
        </div>
        <Toolbar
          hasArchive={hasArchive}
          busy={testing}
          onOpen={open}
          onExtract={() => { setExtractNames(selectedNames); setDialog("extract"); }}
          onCompress={() => setDialog("compress")}
          onTest={runTest}
          onCrack={() => setDialog("crack")}
          onBench={() => setDialog("bench")}
        />
      </header>

      <AddressBar path={path} view={view} onOpen={open} />

      <main className="content">
        <FileList
          view={view}
          loading={loading}
          selected={selected}
          onSelected={setSelected}
          onUnlockHeader={(pw) => load(path, pw)}
          onContextAction={(ev, entry) => setCtxMenu({ x: ev.clientX, y: ev.clientY, entry })}
        />
      </main>

      <footer className="status-bar">
        <span>
          {view
            ? selected.size > 0
              ? `已选 ${selected.size} 项`
              : `${view.entries.length} 个条目`
            : "就绪"}
        </span>
        <span className="sb-right">
          {view?.encryption ? (
            "🔒 加密归档 · 可用「密码找回」"
          ) : (
            <>
              本地处理 · 不联网
              {version ? <span className="sb-ver">RoseZIP v{version}</span> : null}
            </>
          )}
        </span>
      </footer>

      {dialog === "extract" && view && (
        <ExtractDialog
          path={path}
          names={extractNames}
          presetPassword={headerPw}
          defaultDest={defaultExtractDir(path)}
          onClose={() => setDialog(null)}
          onDone={(r) => notify("success", r.message)}
        />
      )}
      {dialog === "compress" && (
        <CompressDialog
          onClose={() => setDialog(null)}
          onDone={async (r) => {
            notify("success", r.message);
            const m = r.message.match(/→ (.+)$/);
            if (m) load(m[1]);
          }}
          pickFiles={pickFiles}
          pickFolder={pickDirectory}
          pickSave={pickZipSave}
        />
      )}
      {dialog === "bench" && <BenchDialog onClose={() => setDialog(null)} />}
      {dialog === "crack" && view && (
        <CrackDialog
          path={path}
          onClose={() => setDialog(null)}
          onFound={(pw) => notify("success", `密码：${pw}`)}
        />
      )}

      {ctxMenu && (
        <RowContextMenu
          x={ctxMenu.x}
          y={ctxMenu.y}
          entry={ctxMenu.entry}
          multi={selected.size}
          onClose={() => setCtxMenu(null)}
          onAction={handleContextAction}
        />
      )}

      {renameTarget && (
        <RenameDialog
          path={path}
          oldName={renameTarget}
          password={headerPw}
          onClose={() => setRenameTarget(null)}
          onDone={async (r) => {
            notify(r.ok ? "success" : "error", r.message);
            setRenameTarget(null);
            if (r.ok) load(path, headerPw);
          }}
        />
      )}
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <Shell />
    </ToastProvider>
  );
}
