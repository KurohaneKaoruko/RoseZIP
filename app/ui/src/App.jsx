import React, { useEffect, useState } from "react";
import ArchivePage from "./pages/ArchivePage";
import BenchPage from "./pages/BenchPage";
import CompressPage from "./pages/CompressPage";
import CrackPage from "./pages/CrackPage";
import { Icon, RoseMark } from "./icons";
import { ToastProvider } from "./ui";

const PAGES = [
  { id: "archive", label: "归档", icon: "archive", component: ArchivePage },
  { id: "compress", label: "压缩", icon: "compress", component: CompressPage },
  { id: "crack", label: "密码恢复", icon: "key", component: CrackPage },
  { id: "bench", label: "基准", icon: "gauge", component: BenchPage },
];

export default function App() {
  const [active, setActive] = useState("archive");
  const [version, setVersion] = useState("");

  useEffect(() => {
    import("@tauri-apps/api/app")
      .then((mod) => mod.getVersion())
      .then(setVersion)
      .catch(() => setVersion("0.1.0"));
  }, []);

  const Active = PAGES.find((p) => p.id === active)?.component ?? ArchivePage;

  return (
    <ToastProvider>
      <div className="app-shell">
        <aside className="sidebar">
          <div className="brand">
            <RoseMark size={30} />
            <div className="brand-text">
              <span className="brand-name">RoseZIP</span>
              <span className="brand-tag">archive · recovery</span>
            </div>
          </div>

          <nav className="nav">
            {PAGES.map((page) => (
              <button
                key={page.id}
                className={`nav-item ${active === page.id ? "active" : ""}`}
                onClick={() => setActive(page.id)}
              >
                <Icon name={page.icon} size={17} />
                <span>{page.label}</span>
              </button>
            ))}
          </nav>

          <div className="sidebar-foot">
            <div className="foot-card">
              <Icon name="shield" size={14} />
              <span>纯本地运行，文件与密码不经过网络。</span>
            </div>
            <div className="foot-version">
              RoseZIP {version ? `v${version}` : ""}
            </div>
          </div>
        </aside>

        <main className="main" key={active}>
          <Active />
        </main>
      </div>
    </ToastProvider>
  );
}
