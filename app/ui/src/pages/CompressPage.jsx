import React, { useState } from "react";
import { invoke, pickDirectory, pickFiles, pickZipSave } from "../api";
import { humanBytes, splitPath } from "../format";
import { Icon } from "../icons";
import {
  Badge,
  Banner,
  Button,
  Card,
  Field,
  IconButton,
  PageHead,
  Segmented,
  useToast,
} from "../ui";

const LEVELS = [
  { value: "0", label: "仅存储" },
  { value: "3", label: "快速" },
  { value: "6", label: "标准" },
  { value: "9", label: "极限" },
];

export default function CompressPage() {
  const notify = useToast();
  const [files, setFiles] = useState([]);
  const [out, setOut] = useState("");
  const [password, setPassword] = useState("");
  const [level, setLevel] = useState("6");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null);

  function addPaths(paths) {
    setFiles((prev) => [...new Set([...prev, ...paths])]);
  }

  async function addFiles() {
    const picked = await pickFiles();
    if (picked.length) addPaths(picked);
  }

  async function addFolder() {
    const dir = await pickDirectory("选择要压缩的目录");
    if (dir) addPaths([dir]);
  }

  async function chooseOut() {
    const target = await pickZipSave(out.trim() || "archive.zip");
    if (target) setOut(target);
  }

  async function compress() {
    if (!files.length) {
      notify("error", "请先添加要压缩的文件或目录");
      return;
    }
    if (!out.trim()) {
      notify("error", "请先选择输出 ZIP 路径");
      return;
    }
    setBusy(true);
    setReport(null);
    try {
      const result = await invoke("compress_archive", {
        files,
        out: out.trim(),
        password: password || null,
        level: Number(level),
      });
      setReport(result);
      if (result.ok) notify("success", "压缩包创建完成");
      else notify("error", result.message);
    } catch (e) {
      notify("error", `压缩失败：${e}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHead
        kicker="CREATE"
        title="创建压缩包"
        desc="把文件和目录打包为 ZIP，可选 ZipCrypto 传统加密，兼容 unzip / 7z / Windows。"
      >
        <Badge tone="rose" icon="compress">
          原生 ZIP 写入
        </Badge>
      </PageHead>

      <div className="compress-layout">
        <Card
          icon="folder"
          title="归档内容"
          sub={`${files.length} 个输入`}
          actions={
            <>
              <Button variant="ghost" size="sm" icon="plus" onClick={addFiles} disabled={busy}>
                添加文件
              </Button>
              <Button variant="ghost" size="sm" icon="folder" onClick={addFolder} disabled={busy}>
                添加目录
              </Button>
            </>
          }
        >
          {files.length === 0 ? (
            <div className="dropzone">
              <div className="dropzone-icon">
                <Icon name="upload" size={24} />
              </div>
              <h4>添加要压缩的内容</h4>
              <p>支持多选文件，也可以直接选择整个目录；目录会递归打包。</p>
              <div className="row" style={{ justifyContent: "center", marginTop: 12 }}>
                <Button size="sm" icon="plus" onClick={addFiles} disabled={busy}>
                  选择文件
                </Button>
                <Button variant="ghost" size="sm" icon="folder" onClick={addFolder} disabled={busy}>
                  选择目录
                </Button>
              </div>
            </div>
          ) : (
            <>
              <div className="file-list">
                {files.map((f) => {
                  const { base, dir } = splitPath(f);
                  return (
                    <div className="file-row" key={f}>
                      <span className="file-row-icon">
                        <Icon name="file" size={15} />
                      </span>
                      <div className="file-main">
                        <div className="file-name">{base || f}</div>
                        {dir && <div className="file-dir">{dir}</div>}
                      </div>
                      <IconButton
                        icon="x"
                        label="移除"
                        className="row-remove"
                        onClick={() => setFiles((prev) => prev.filter((x) => x !== f))}
                        disabled={busy}
                      />
                    </div>
                  );
                })}
              </div>
              <div className="file-summary">
                <Icon name="info" size={13} />
                <span>同名文件会保留最后添加的一份；目录内文件保留相对路径。</span>
              </div>
            </>
          )}
        </Card>

        <Card icon="compress" title="输出设置" sub="ZIP 格式 · Deflate 压缩">
          <div className="stack">
            <Field label="输出文件">
              <div className="row">
                <input
                  className="input mono grow"
                  value={out}
                  onChange={(e) => setOut(e.target.value)}
                  placeholder="archive.zip"
                  spellCheck={false}
                />
                <Button variant="ghost" icon="external" onClick={chooseOut} disabled={busy}>
                  另存为
                </Button>
              </div>
            </Field>

            <Field label="压缩级别" hint="Deflate 0–9">
              <Segmented options={LEVELS} value={level} onChange={setLevel} disabled={busy} label="压缩级别" />
            </Field>

            <Field label="加密密码" hint="可选">
              <input
                className="input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="留空则不加密"
                autoComplete="new-password"
              />
            </Field>

            <Banner tone="info">
              ZipCrypto 兼容性最好，但强度有限；高机密文件建议使用 7z AES-256。
            </Banner>

            <Button
              icon="compress"
              onClick={compress}
              loading={busy}
              disabled={busy || !files.length || !out.trim()}
              className="btn-block"
            >
              创建压缩包
            </Button>
          </div>
        </Card>
      </div>

      {report && (
        <Banner tone={report.ok ? "success" : "error"} onClose={() => setReport(null)}>
          {report.message}
          {report.errors?.length > 0 && (
            <ul className="banner-list">
              {report.errors.map((err, i) => (
                <li key={i}>{err}</li>
              ))}
            </ul>
          )}
        </Banner>
      )}

      <div className="tip-grid">
        <div className="tip-card">
          <span className="tip-icon">
            <Icon name="shield" size={16} />
          </span>
          <h4>ZipCrypto 兼容加密</h4>
          <p>生成传统 PKZIP 加密条目，unzip、7-Zip、Windows 资源管理器均可解压。</p>
        </div>
        <div className="tip-card">
          <span className="tip-icon">
            <Icon name="folder" size={16} />
          </span>
          <h4>保留目录结构</h4>
          <p>选择目录时会递归读取全部文件，并在归档内保留相对路径。</p>
        </div>
        <div className="tip-card">
          <span className="tip-icon">
            <Icon name="gauge" size={16} />
          </span>
          <h4>快速 Deflate</h4>
          <p>原生 Rust 压缩管线，存储 / 快速 / 标准 / 极限四档可选。</p>
        </div>
      </div>
    </>
  );
}
