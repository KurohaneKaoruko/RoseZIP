import React, { useCallback, useEffect, useState } from "react";
import { invoke, pickArchive, pickDirectory, pickFiles, pickZipSave } from "./api";
import { defaultExtractDir } from "./format";
import { RoseMark } from "./icons";
import { ToastProvider, useToast } from "./ui";
import Toolbar, { AddressBar } from "./components/Toolbar";
import FileList from "./components/FileList";
import { BenchDialog, CompressDialog, CrackDialog, ExtractDialog } from "./components/Dialogs";

function Shell() {
  const notify = useToast();
  const [path, setPath] = useState("");
  const [view, setView] = useState(null);
  const [loading, setLoading] = useState(false);
  const [dialog, setDialog] = useState(null); // null | 'extract' | 'compress' | 'bench' | 'crack'
  const [version, setVersion] = useState("");

  useEffect(() => {
    invoke("app_version").then(setVersion).catch(() => {});
  }, []);

  const load = useCallback(
    async (p) => {
      if (!p) return;
      setLoading(true);
      try {
        const v = await invoke("inspect_archive", { path: p });
        setPath(v.path || p);
        setView(v);
      } catch (e) {
        notify("error", `无法读取：${e}`);
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

  const hasArchive = Boolean(view) || loading;

  return (
    <div className="app-shell">
      <header className="top">
        <div className="brand-mini">
          <RoseMark size={20} />
          <span className="brand-mini-name">RoseZIP</span>
        </div>
        <Toolbar
          hasArchive={hasArchive}
          busy={dialog === "compress"}
          onOpen={open}
          onExtract={() => setDialog("extract")}
          onCompress={() => setDialog("compress")}
          onCrack={() => setDialog("crack")}
          onBench={() => setDialog("bench")}
        />
      </header>

      <AddressBar path={path} view={view} onOpen={open} />

      <main className="content">
        <FileList view={view} loading={loading} />
      </main>

      <footer className="status-bar">
        <span>{view ? `${view.entries.length} 个条目` : "就绪"}</span>
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
            // 若输出路径可读，直接打开它
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
