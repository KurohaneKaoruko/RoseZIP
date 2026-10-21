import React, { useCallback, useEffect, useState } from "react";
import { invoke, pickArchive, pickDirectory, pickFiles, pickZipSave, getCurrentWebview } from "./api";
import { defaultExtractDir } from "./format";
import { RoseMark } from "./icons";
import { ToastProvider, useToast } from "./ui";
import Toolbar, { AddressBar } from "./components/Toolbar";
import FileList from "./components/FileList";
import { BenchDialog, CompressDialog, CrackDialog, ExtractDialog } from "./components/Dialogs";

const ARCHIVE_RE = /\.(zip|7z|tar|gz|tgz|xz|bz2)$/i;

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
