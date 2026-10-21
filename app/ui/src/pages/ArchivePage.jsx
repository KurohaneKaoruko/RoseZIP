import React, { useMemo, useState } from "react";
import { invoke, pickArchive, pickDirectory } from "../api";
import { defaultExtractDir, humanBytes } from "../format";
import { Icon } from "../icons";
import {
  Badge,
  Banner,
  Button,
  Card,
  EmptyState,
  Field,
  PageHead,
  Stat,
  useToast,
} from "../ui";

const FORMAT_NAMES = {
  Zip: "ZIP",
  SevenZ: "7Z",
  Tar: "TAR",
  Gz: "GZIP",
  Xz: "XZ",
  Bz2: "BZIP2",
};

function encryptionBadge(encryption, format) {
  if (!encryption) return { tone: "green", icon: "unlock", label: "未加密" };
  if (format === "SevenZ")
    return { tone: "violet", icon: "shield", label: "7z AES-256" };
  if (encryption.includes("AES"))
    return { tone: "violet", icon: "shield", label: "WinZip AES" };
  if (encryption.includes("ZipCrypto"))
    return { tone: "amber", icon: "lock", label: "ZipCrypto" };
  return { tone: "amber", icon: "lock", label: "已加密" };
}

export default function ArchivePage() {
  const notify = useToast();
  const [path, setPath] = useState("");
  const [view, setView] = useState(null);
  const [loading, setLoading] = useState(false);
  const [dest, setDest] = useState("");
  const [password, setPassword] = useState("");
  const [extracting, setExtracting] = useState(false);
  const [report, setReport] = useState(null);

  const totals = useMemo(() => {
    if (!view) return null;
    return view.entries.reduce(
      (acc, e) => {
        if (!e.is_dir) {
          acc.files += 1;
          acc.packed += e.compressed_size;
          acc.size += e.uncompressed_size;
        }
        return acc;
      },
      { files: 0, packed: 0, size: 0 }
    );
  }, [view]);

  const encryptedCount = view
    ? view.entries.filter((e) => e.encrypted && !e.is_dir).length
    : 0;
  const enc = encryptionBadge(view?.encryption, view?.format);

  async function browse() {
    const picked = await pickArchive();
    if (!picked) return;
    setPath(picked);
    setView(null);
    setReport(null);
    setDest(defaultExtractDir(picked));
  }

  async function inspect() {
    const p = path.trim();
    if (!p) return;
    setLoading(true);
    setReport(null);
    try {
      const result = await invoke("inspect_archive", { path: p });
      setView(result);
      if (!dest.trim()) setDest(defaultExtractDir(p));
    } catch (e) {
      setView(null);
      notify("error", `无法读取归档：${e}`);
    } finally {
      setLoading(false);
    }
  }

  async function extract() {
    if (!view) return;
    const target = dest.trim() || defaultExtractDir(path.trim());
    setExtracting(true);
    setReport(null);
    try {
      const result = await invoke("extract_archive", {
        path: path.trim(),
        dest: target,
        password: password || null,
      });
      setReport(result);
      if (result.ok && result.errors.length === 0) {
        notify("success", result.message);
      } else {
        notify("warning", "解压完成，但有文件未成功");
      }
    } catch (e) {
      notify("error", `解压失败：${e}`);
    } finally {
      setExtracting(false);
    }
  }

  return (
    <>
      <PageHead
        kicker="ARCHIVE"
        title="归档浏览"
        desc="查看归档结构与加密类型，安全地解压到指定目录。"
      >
        <Badge tone="green" icon="shield">
          本地处理 · 数据不出机器
        </Badge>
      </PageHead>

      <Card
        icon="search"
        title="打开归档"
        sub="ZIP · 7Z · TAR · GZ · XZ · BZ2"
        actions={
          <Button
            variant="ghost"
            size="sm"
            icon="folder"
            onClick={browse}
            disabled={loading}
          >
            浏览
          </Button>
        }
      >
        <div className="row">
          <input
            className="input mono grow"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") inspect();
            }}
            placeholder="/path/to/archive.zip"
            spellCheck={false}
          />
          <Button icon="search" onClick={inspect} loading={loading} disabled={!path.trim()}>
            查看
          </Button>
        </div>

        {view && (
          <>
            <div className="stats" style={{ marginTop: 16 }}>
              <Stat label="格式" value={FORMAT_NAMES[view.format] || view.format} />
              <Stat
                label="加密"
                value={enc.label}
                sub={view.encryption ? `${encryptedCount} 个加密条目` : "无密码保护"}
                tone={view.encryption ? "rose" : "green"}
              />
              <Stat label="文件数" value={totals?.files ?? 0} sub={`共 ${view.entries.length} 个条目`} />
              <Stat label="原始大小" value={humanBytes(totals?.size ?? 0)} sub={`压缩后 ${humanBytes(totals?.packed ?? 0)}`} />
            </div>
            {view.encryption && (
              <div className="enc-line">
                <Icon name={enc.icon} size={14} />
                <span>{view.encryption}</span>
              </div>
            )}
          </>
        )}
      </Card>

      <Card
        icon="archive"
        title="内容列表"
        sub={view ? `${view.entries.length} 个条目` : "打开归档后显示文件清单"}
        actions={view ? <Badge tone={enc.tone} icon={enc.icon}>{enc.label}</Badge> : null}
      >
        {!view ? (
          <EmptyState
            icon="archive"
            title="还没有打开归档"
            desc="选择一个 ZIP / 7z / tar 等归档文件，或直接输入路径后点击「查看」。"
          >
            <Button variant="ghost" size="sm" icon="folder" onClick={browse}>
              选择文件
            </Button>
          </EmptyState>
        ) : view.entries.length === 0 ? (
          <EmptyState icon="file" title="归档为空" desc="这个归档中没有可显示的条目。" />
        ) : (
          <div className="table-wrap">
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>名称</th>
                    <th className="w-enc">加密</th>
                    <th className="num">压缩后</th>
                    <th className="num">原始大小</th>
                  </tr>
                </thead>
                <tbody>
                  {view.entries.map((entry, i) => (
                    <tr key={`${entry.name}-${i}`}>
                      <td>
                        <span className="name-cell">
                          <Icon
                            name={entry.is_dir ? "folder" : "file"}
                            size={14}
                            className={entry.is_dir ? "file-ico folder" : "file-ico"}
                          />
                          <span className={entry.is_dir ? "entry-dir" : "entry-name"}>
                            {entry.name}
                            {entry.is_dir ? "/" : ""}
                          </span>
                        </span>
                      </td>
                      <td>
                        {entry.encrypted ? (
                          <span className="lock-pill">
                            <Icon name="lock" size={11} />
                            AES / ZC
                          </span>
                        ) : (
                          <span className="dim">—</span>
                        )}
                      </td>
                      <td className="num">{entry.is_dir ? "—" : humanBytes(entry.compressed_size)}</td>
                      <td className="num">{entry.is_dir ? "—" : humanBytes(entry.uncompressed_size)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Card>

      <Card
        icon="download"
        title="解压"
        sub="加密归档需要填写正确密码；输出目录会自动创建"
        actions={
          view && encryptedCount > 0 ? (
            <Badge tone="amber" icon="key">
              {encryptedCount} 个条目需要密码
            </Badge>
          ) : null
        }
      >
        <div className="form-grid-2">
          <Field label="输出目录">
            <div className="row">
              <input
                className="input mono grow"
                value={dest}
                onChange={(e) => setDest(e.target.value)}
                placeholder="留空则使用归档同目录下的 *_extracted"
                spellCheck={false}
              />
              <Button
                variant="ghost"
                icon="folder"
                onClick={async () => {
                  const dir = await pickDirectory("选择解压目录");
                  if (dir) setDest(dir);
                }}
              >
                浏览
              </Button>
            </div>
          </Field>
          <Field label="密码" hint="未加密可留空">
            <input
              className="input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="off"
            />
          </Field>
        </div>

        <div className="form-actions">
          <Button
            icon="download"
            onClick={extract}
            loading={extracting}
            disabled={!view || extracting}
          >
            开始解压
          </Button>
          <span className="hint">
            {view
              ? encryptedCount > 0
                ? "请先确认密码正确，否则加密条目的 CRC 校验会失败。"
                : "归档未加密，可直接解压。"
              : "先打开一个归档文件。"}
          </span>
        </div>

        {report && (
          <div style={{ marginTop: 14 }}>
            <Banner tone={report.ok ? "success" : "warning"} onClose={() => setReport(null)}>
              <div>{report.message}</div>
              {report.errors?.length > 0 && (
                <ul className="banner-list">
                  {report.errors.slice(0, 5).map((err, i) => (
                    <li key={i}>{err}</li>
                  ))}
                </ul>
              )}
              {report.errors?.length > 5 && (
                <div className="dim">还有 {report.errors.length - 5} 条错误未显示…</div>
              )}
            </Banner>
          </div>
        )}
      </Card>
    </>
  );
}
