import React, { useEffect, useRef, useState } from "react";
import { invoke } from "../api";
import { formatDuration, humanCount, percentText } from "../format";
import { Icon } from "../icons";
import { Banner, Button } from "../ui";

/** 通用弹窗壳：Esc 关闭，点遮罩不关（防误触丢输入）。 */
export function Modal({ title, icon, onClose, children, footer, wide }) {
  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose?.();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="modal-mask" onMouseDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className={`modal ${wide ? "modal-wide" : ""}`} role="dialog" aria-label={title}>
        <div className="modal-head">
          <span className="modal-icon">
            <Icon name={icon} size={15} />
          </span>
          <span className="modal-title">{title}</span>
          <button className="modal-close" onClick={onClose} aria-label="关闭">
            <Icon name="x" size={14} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

/** 解压弹窗：目录 + 密码 + 结果。支持只解压选中项。 */
export function ExtractDialog({ path, names, presetPassword, defaultDest, onClose, onDone }) {
  const [dest, setDest] = useState(() => {
    try {
      return localStorage.getItem("rosezip.lastDest") || defaultDest || "";
    } catch {
      return defaultDest || "";
    }
  });
  const [password, setPassword] = useState(presetPassword || "");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  async function run() {
    setBusy(true);
    setResult(null);
    const target = dest.trim() || defaultDest;
    try {
      localStorage.setItem("rosezip.lastDest", target);
    } catch { /* ignore */ }
    try {
      const r = names
        ? await invoke("extract_selected", { path, names, dest: target, password: password || null })
        : await invoke("extract_archive", { path, dest: target, password: password || null });
      setResult(r);
      if (r.ok && r.errors.length === 0) onDone?.(r);
    } catch (e) {
      setResult({ ok: false, message: String(e), errors: [] });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="解压"
      icon="download"
      onClose={busy ? undefined : onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            关闭
          </Button>
          <Button icon="download" onClick={run} loading={busy}>
            {result?.ok ? "再次解压" : "解压"}
          </Button>
        </>
      }
    >
      <div className="form-rows">
        {names && names.length > 0 && (
          <div className="frow">
            <span className="frow-label">范围</span>
            <div className="frow-main sel-hint">
              只解压选中的 <b>{names.length}</b> 个条目
            </div>
          </div>
        )}
        <label className="frow">
          <span className="frow-label">输出目录</span>
          <input
            className="input mono"
            value={dest}
            onChange={(e) => setDest(e.target.value)}
            placeholder={defaultDest}
            spellCheck={false}
          />
        </label>
        <label className="frow">
          <span className="frow-label">密码</span>
          <input
            className="input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="加密归档时填写"
            autoComplete="off"
          />
        </label>
      </div>
      {result && (
        <div className="modal-result">
          <Banner tone={result.ok ? "success" : "warning"}>
            {result.message}
            {result.errors?.length > 0 && (
              <ul className="banner-list">
                {result.errors.slice(0, 4).map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            )}
          </Banner>
        </div>
      )}
    </Modal>
  );
}

/** 压缩弹窗：输入文件列表 + 输出 + 密码 + 级别。 */
export function CompressDialog({ onClose, onDone, pickFiles, pickFolder, pickSave }) {
  const [files, setFiles] = useState([]);
  const [out, setOut] = useState("");
  const [password, setPassword] = useState("");
  const [level, setLevel] = useState("6");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [manual, setManual] = useState("");
  const fileRef = useRef(null);

  useEffect(() => {
    fileRef.current?.focus();
  }, []);

  function addPaths(paths) {
    setFiles((prev) => [...new Set([...prev, ...paths])]);
  }

  async function run() {
    if (!files.length || !out.trim()) return;
    setBusy(true);
    setResult(null);
    try {
      const r = await invoke("compress_archive", {
        files,
        out: out.trim(),
        password: password || null,
        level: Number(level),
      });
      setResult(r);
      if (r.ok) onDone?.(r);
    } catch (e) {
      setResult({ ok: false, message: String(e), errors: [] });
    } finally {
      setBusy(false);
    }
  }

  const valid = files.length > 0 && out.trim().length > 0;

  return (
    <Modal
      title="新建压缩包"
      icon="compress"
      onClose={busy ? undefined : onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            关闭
          </Button>
          <Button icon="compress" onClick={run} loading={busy} disabled={!valid}>
            压缩
          </Button>
        </>
      }
    >
      <div className="form-rows">
        <div className="frow">
          <span className="frow-label">文件</span>
          <div className="frow-main stack-tight">
            {files.length === 0 ? (
              <div className="mini-drop" onClick={async () => addPaths(await pickFiles())}>
                <Icon name="plus" size={14} />
                <span>点击选择文件 / 目录</span>
              </div>
            ) : (
              <>
                <div className="mini-list">
                  {files.map((f) => (
                    <div className="mini-row" key={f} title={f}>
                      <Icon name="file" size={12} className="fl-ico" />
                      <span className="mini-name mono">{f}</span>
                      <button
                        className="mini-x"
                        onClick={() => setFiles((p) => p.filter((x) => x !== f))}
                        aria-label="移除"
                      >
                        <Icon name="x" size={11} />
                      </button>
                    </div>
                  ))}
                </div>
                <div className="mini-actions">
                  <button className="link-btn" onClick={async () => addPaths(await pickFiles())}>
                    + 文件
                  </button>
                  <button className="link-btn" onClick={async () => addPaths([await pickFolder()])}>
                    + 目录
                  </button>
                  <span className="mini-or">或输入路径</span>
                  <input
                    className="input mini-path-input mono"
                    value={manual}
                    onChange={(e) => setManual(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && manual.trim()) {
                        addPaths([manual.trim()]);
                        setManual("");
                      }
                    }}
                    placeholder="/path/to/file"
                    spellCheck={false}
                    disabled={busy}
                  />
                  <button
                    className="link-btn"
                    onClick={() => {
                      if (manual.trim()) {
                        addPaths([manual.trim()]);
                        setManual("");
                      }
                    }}
                    disabled={busy}
                  >
                    添加
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
        <label className="frow">
          <span className="frow-label">输出</span>
          <div className="frow-main row-tight">
            <input
              ref={fileRef}
              className="input mono grow"
              value={out}
              onChange={(e) => setOut(e.target.value)}
              placeholder="archive.zip"
              spellCheck={false}
            />
            <Button
              variant="ghost"
              size="sm"
              onClick={async () => {
                const p = await pickSave(out.trim() || "archive.zip");
                if (p) setOut(p);
              }}
              disabled={busy}
            >
              浏览
            </Button>
          </div>
        </label>
        <div className="frow">
          <span className="frow-label">密码</span>
          <input
            className="input frow-main"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="留空不加密 (ZipCrypto)"
            autoComplete="new-password"
          />
        </div>
        <div className="frow">
          <span className="frow-label">级别</span>
          <div className="frow-main seg-tight">
            {[
              ["0", "存储"],
              ["3", "快速"],
              ["6", "标准"],
              ["9", "极限"],
            ].map(([v, l]) => (
              <button
                key={v}
                className={level === v ? "active" : ""}
                onClick={() => setLevel(v)}
                disabled={busy}
              >
                {l}
              </button>
            ))}
          </div>
        </div>
      </div>
      {result && (
        <div className="modal-result">
          <Banner tone={result.ok ? "success" : "error"}>{result.message}</Banner>
        </div>
      )}
    </Modal>
  );
}

/** 基准测试弹窗。 */
export function BenchDialog({ onClose }) {
  const [busy, setBusy] = useState(false);
  const [bench, setBench] = useState(null);

  async function run() {
    setBusy(true);
    try {
      setBench(await invoke("bench_speed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="性能测试"
      icon="gauge"
      onClose={busy ? undefined : onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            关闭
          </Button>
          <Button icon="zap" onClick={run} loading={busy}>
            {bench ? "重测" : "开始"}
          </Button>
        </>
      }
    >
      <div className="bench-compact">
        <div className="bc-row">
          <span>ZipCrypto 校验速度</span>
          <b className="mono">
            {bench ? `${(bench.zipcrypto_per_sec / 1e6).toFixed(2)}M/s` : "—"}
          </b>
        </div>
        <div className="bc-row">
          <span>WinZip AES 估算</span>
          <b className="mono">
            {bench ? `${humanCount(bench.aes_per_sec)}/s` : "—"}
          </b>
        </div>
        <div className="bc-row dim-row">
          <span>线程</span>
          <b className="mono">{bench ? bench.threads : "—"}</b>
        </div>
        <p className="bc-note">ZipCrypto 可全速穷举；AES 因 PBKDF2 约慢 1000 倍，建议字典。</p>
      </div>
    </Modal>
  );
}

/** 密码找回弹窗：检测 + 模式 + 实时进度。 */
export function CrackDialog({ path, onClose, onFound }) {
  const [info, setInfo] = useState(null);
  const [mode, setMode] = useState("brute");
  const [charset, setCharset] = useState("lower");
  const [minLen, setMinLen] = useState(1);
  const [maxLen, setMaxLen] = useState(6);
  const [dictionary, setDictionary] = useState("");
  const [space, setSpace] = useState(null);
  const [status, setStatus] = useState(null);
  const [starting, setStarting] = useState(false);
  const [running, setRunning] = useState(false);
  const timer = useRef(null);

  const isAes = Boolean(info?.kind?.toLowerCase().includes("aes"));
  const is7z = Boolean(info?.kind?.toLowerCase().includes("7z"));

  useEffect(() => {
    let alive = true;
    invoke("crack_prepare", { path })
      .then((r) => alive && setInfo(r))
      .catch((e) => alive && setInfo({ error: String(e) }));
    return () => {
      alive = false;
    };
  }, [path]);

  useEffect(() => {
    if (mode !== "brute") return undefined;
    let alive = true;
    const t = window.setTimeout(async () => {
      try {
        const r = await invoke("estimate_space", {
          charset: charset.trim() || "lower",
          minLen,
          maxLen,
        });
        if (alive) setSpace(r);
      } catch {
        if (alive) setSpace(null);
      }
    }, 200);
    return () => {
      alive = false;
      window.clearTimeout(t);
    };
  }, [mode, charset, minLen, maxLen]);

  useEffect(
    () => () => {
      if (timer.current) window.clearInterval(timer.current);
    },
    []
  );

  async function start() {
    setStarting(true);
    try {
      const params = { path, mode, threads: null };
      if (mode === "brute") {
        Object.assign(params, {
          charset: charset.trim() || "lower",
          minLen,
          maxLen,
        });
      } else {
        params.dictionary = dictionary.trim();
      }
      const initial = await invoke("crack_start", params);
      setStatus(initial);
      setRunning(true);
      if (timer.current) window.clearInterval(timer.current);
      timer.current = window.setInterval(async () => {
        try {
          const st = await invoke("crack_status");
          setStatus(st);
          if (st.finished) {
            window.clearInterval(timer.current);
            timer.current = null;
            setRunning(false);
            if (st.found) onFound?.(st.found);
          }
        } catch {
          window.clearInterval(timer.current);
          timer.current = null;
          setRunning(false);
        }
      }, 200);
    } catch (e) {
      setStatus({ error: String(e) });
    } finally {
      setStarting(false);
    }
  }

  async function stop() {
    try {
      await invoke("crack_cancel");
    } catch {
      /* ignore */
    }
  }

  const pct = status?.total ? (status.done / status.total) * 100 : null;
  const rate = status?.rate_per_sec || 0;
  const eta = status?.total && rate > 0 ? Math.max(0, (status.total - status.done) / rate) : null;

  return (
    <Modal
      title="密码找回"
      icon="key"
      wide
      onClose={running ? undefined : onClose}
      footer={
        running ? (
          <Button variant="danger" icon="stop" onClick={stop}>
            停止
          </Button>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose}>
              关闭
            </Button>
            <Button
              icon="play"
              onClick={start}
              loading={starting}
              disabled={mode === "dictionary" && !dictionary.trim()}
            >
              开始
            </Button>
          </>
        )
      }
    >
      {info?.error ? (
        <Banner tone="error">{info.error}</Banner>
      ) : (
        <>
          <div className="ck-meta">
            {info ? (
              <>
                <span className={`badge ${isAes || is7z ? "badge-violet" : "badge-amber"}`}>
                  <Icon name="lock" size={11} /> {info.kind}
                </span>
                <span className="ck-entry mono">{info.entry}</span>
              </>
            ) : (
              <span className="dim">检测加密类型…</span>
            )}
          </div>

          <div className="form-rows">
            <div className="frow">
              <span className="frow-label">模式</span>
              <div className="frow-main seg-tight">
                <button className={mode === "brute" ? "active" : ""} onClick={() => setMode("brute")} disabled={running}>
                  暴力
                </button>
                <button
                  className={mode === "dictionary" ? "active" : ""}
                  onClick={() => setMode("dictionary")}
                  disabled={running}
                >
                  字典
                </button>
              </div>
            </div>

            {mode === "brute" ? (
              <>
                <div className="frow">
                  <span className="frow-label">字符集</span>
                  <div className="frow-main chips-tight">
                    {[
                      ["lower", "小写"],
                      ["digits", "数字"],
                      ["lower+digits", "小写+数字"],
                      ["alnum", "字母+数字"],
                      ["all", "全部"],
                    ].map(([v, l]) => (
                      <button
                        key={v}
                        className={`chip-s ${charset === v ? "active" : ""}`}
                        onClick={() => setCharset(v)}
                        disabled={running}
                      >
                        {l}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="frow">
                  <span className="frow-label">长度</span>
                  <div className="frow-main row-tight">
                    <input
                      className="input num-s"
                      type="number"
                      min={1}
                      max={32}
                      value={minLen}
                      disabled={running}
                      onChange={(e) => {
                        const n = Math.min(32, Math.max(1, +e.target.value || 1));
                        setMinLen(n);
                        if (n > maxLen) setMaxLen(n);
                      }}
                    />
                    <span className="dim">→</span>
                    <input
                      className="input num-s"
                      type="number"
                      min={1}
                      max={32}
                      value={maxLen}
                      disabled={running}
                      onChange={(e) => {
                        const n = Math.min(32, Math.max(1, +e.target.value || 1));
                        setMaxLen(n);
                        if (n < minLen) setMinLen(n);
                      }}
                    />
                    <span className="ck-space mono">{space ? space.total_pretty : ""}</span>
                  </div>
                </div>
                {(isAes || is7z) && (
                  <Banner tone="warning">
                    {is7z ? "7z" : "WinZip AES"} 每候选需完整密钥派生
                    {is7z ? "（约 30ms）" : "（约 1ms）"}，暴力很慢，强烈建议字典模式。
                  </Banner>
                )}
              </>
            ) : (
              <label className="frow">
                <span className="frow-label">字典</span>
                <div className="frow-main row-tight">
                  <input
                    className="input mono grow"
                    value={dictionary}
                    onChange={(e) => setDictionary(e.target.value)}
                    placeholder="wordlist.txt（每行一个密码）"
                    spellCheck={false}
                    disabled={running}
                  />
                </div>
              </label>
            )}
          </div>

          {status && !status.error && (
            <div className="ck-progress">
              <div className="ck-line">
                <span className="ck-pct">{status.total ? percentText(pct) : humanCount(status.done)}</span>
                <span className="ck-rate mono">
                  {humanCount(rate)}/s · 已用 {formatDuration(status.elapsed_secs)}
                  {eta !== null && !status.finished ? ` · 剩余 ~${formatDuration(eta)}` : ""}
                </span>
              </div>
              <div className={`progress ${status.total ? "" : "indet"} ${status.finished ? "done" : ""}`}>
                <div
                  className="progress-fill"
                  style={status.total ? { width: `${Math.min(100, pct)}%` } : undefined}
                />
              </div>
              {status.found && (
                <div className="ck-found">
                  <Icon name="key" size={16} />
                  <span className="ck-found-label">已找回</span>
                  <b className="ck-found-pw mono">{status.found}</b>
                </div>
              )}
              {status.finished && !status.found && (
                <div className="dim" style={{ marginTop: 8 }}>
                  {status.cancelled ? "已停止。" : "未找到。"} 试试扩大范围或更换字典。
                </div>
              )}
              {!status.finished && status.cancelled && (
                <div className="dim" style={{ marginTop: 8 }}>
                  正在停止…
                </div>
              )}
            </div>
          )}
          {status?.error && <Banner tone="error">{status.error}</Banner>}
        </>
      )}
    </Modal>
  );
}
