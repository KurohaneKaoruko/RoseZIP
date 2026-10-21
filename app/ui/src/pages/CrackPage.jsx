import React, { useEffect, useRef, useState } from "react";
import { invoke, pickArchive, pickDictionary } from "../api";
import { copyText, formatDuration, humanCount, percentText } from "../format";
import { Icon } from "../icons";
import {
  Badge,
  Banner,
  Button,
  Card,
  Field,
  PageHead,
  Segmented,
  Stat,
  useToast,
} from "../ui";

const PRESETS = [
  { value: "lower", label: "小写", detail: "a–z" },
  { value: "digits", label: "数字", detail: "0–9" },
  { value: "lower+digits", label: "小写+数字", detail: "36" },
  { value: "alnum", label: "字母+数字", detail: "62" },
  { value: "all", label: "全部字符", detail: "90" },
];

const clampLen = (value) => {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return 1;
  return Math.min(32, Math.max(1, n));
};

export default function CrackPage() {
  const notify = useToast();
  const [path, setPath] = useState("");
  const [info, setInfo] = useState(null);
  const [detecting, setDetecting] = useState(false);
  const [mode, setMode] = useState("brute");
  const [charset, setCharset] = useState("lower");
  const [minLen, setMinLen] = useState(1);
  const [maxLen, setMaxLen] = useState(6);
  const [space, setSpace] = useState(null);
  const [dictionary, setDictionary] = useState("");
  const [status, setStatus] = useState(null);
  const [starting, setStarting] = useState(false);
  const [running, setRunning] = useState(false);
  const [copied, setCopied] = useState(false);
  const timer = useRef(null);

  const activeInfo = info && info.path === path.trim() ? info : null;
  const pct = status?.total ? (status.done / status.total) * 100 : null;
  const rate = status?.rate_per_sec || 0;
  const eta =
    status?.total && rate > 0
      ? Math.max(0, (status.total - status.done) / rate)
      : null;
  const isAes = Boolean(activeInfo?.kind?.toLowerCase().includes("aes"));

  // Live estimate of the brute-force search space.
  useEffect(() => {
    if (mode !== "brute") return undefined;
    let alive = true;
    const deadline = window.setTimeout(async () => {
      try {
        const result = await invoke("estimate_space", {
          charset: charset.trim() || "lower",
          minLen,
          maxLen,
        });
        if (alive) setSpace(result);
      } catch {
        if (alive) setSpace(null);
      }
    }, 220);
    return () => {
      alive = false;
      window.clearTimeout(deadline);
    };
  }, [mode, charset, minLen, maxLen]);

  useEffect(
    () => () => {
      if (timer.current) window.clearInterval(timer.current);
    },
    []
  );

  function beginPolling() {
    if (timer.current) window.clearInterval(timer.current);
    timer.current = window.setInterval(async () => {
      try {
        const st = await invoke("crack_status");
        setStatus(st);
        if (st.finished) {
          window.clearInterval(timer.current);
          timer.current = null;
          setRunning(false);
        }
      } catch (e) {
        window.clearInterval(timer.current);
        timer.current = null;
        setRunning(false);
        notify("error", `读取进度失败：${e}`);
      }
    }, 180);
  }

  async function browse() {
    const picked = await pickArchive();
    if (!picked) return;
    setPath(picked);
    setInfo(null);
    setStatus(null);
    setRunning(false);
    setCopied(false);
  }

  async function detect() {
    const p = path.trim();
    if (!p) return;
    setDetecting(true);
    try {
      const result = await invoke("crack_prepare", { path: p });
      setInfo({ ...result, path: p });
      notify("success", `已识别 ${result.kind} 加密`);
    } catch (e) {
      setInfo(null);
      notify("error", `检测失败：${e}`);
    } finally {
      setDetecting(false);
    }
  }

  async function start() {
    const p = path.trim();
    if (!p) {
      notify("error", "请先选择要恢复密码的归档");
      return;
    }
    if (mode === "dictionary" && !dictionary.trim()) {
      notify("error", "字典攻击需要选择一个字典文件");
      return;
    }
    setStarting(true);
    setCopied(false);
    try {
      const prepared = await invoke("crack_prepare", { path: p });
      setInfo({ ...prepared, path: p });

      const params = { path: p, mode, threads: null };
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
      beginPolling();
      notify("info", "攻击任务已启动");
    } catch (e) {
      notify("error", `无法启动攻击：${e}`);
    } finally {
      setStarting(false);
    }
  }

  async function cancel() {
    try {
      await invoke("crack_cancel");
      notify("info", "正在停止任务…");
    } catch (e) {
      notify("error", String(e));
    }
  }

  async function copyPassword() {
    if (!status?.found) return;
    const ok = await copyText(status.found);
    if (ok) {
      setCopied(true);
      notify("success", "密码已复制到剪贴板");
      window.setTimeout(() => setCopied(false), 1600);
    } else {
      notify("error", "复制失败，请手动选择密码");
    }
  }

  return (
    <>
      <PageHead
        kicker="RECOVERY"
        title="密码恢复"
        desc="对加密 ZIP 进行高速字典或暴力破解。仅用于恢复您本人文件的密码。"
      >
        <Badge tone="amber" icon="zap">
          多核并行
        </Badge>
      </PageHead>

      <Card
        icon="search"
        title="目标归档"
        sub="支持 ZipCrypto 与 WinZip AES 加密的 ZIP"
        actions={
          <Button
            variant="ghost"
            size="sm"
            icon="folder"
            onClick={browse}
            disabled={running || detecting}
          >
            浏览
          </Button>
        }
      >
        <div className="row">
          <input
            className="input mono grow"
            value={path}
            onChange={(e) => {
              setPath(e.target.value);
              setInfo(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") detect();
            }}
            placeholder="/path/to/encrypted.zip"
            spellCheck={false}
            disabled={running}
          />
          <Button
            variant="ghost"
            icon="shield"
            onClick={detect}
            loading={detecting}
            disabled={!path.trim() || running}
          >
            检测
          </Button>
        </div>

        {activeInfo ? (
          <div className="target-meta">
            <Badge tone={isAes ? "violet" : "amber"} icon="lock">
              {activeInfo.kind}
            </Badge>
            <span className="meta-text">
              目标条目 <code>{activeInfo.entry}</code>
            </span>
            <span className="meta-sep" />
            <span className="meta-text dim">
              {activeInfo.encrypted_entries} 个加密条目
            </span>
          </div>
        ) : (
          <div className="target-meta placeholder">
            <Icon name="info" size={13} />
            <span>点击「检测」确认加密类型；开始攻击时也会自动识别。</span>
          </div>
        )}
      </Card>

      <div className="crack-layout">
        <Card
          icon="key"
          title="攻击配置"
          sub={mode === "brute" ? "逐位穷举完整搜索空间" : "按行尝试字典中的密码"}
        >
          <div className="stack">
            <Field label="攻击模式">
              <Segmented
                label="攻击模式"
                options={[
                  { value: "brute", label: "暴力破解" },
                  { value: "dictionary", label: "字典攻击" },
                ]}
                value={mode}
                onChange={setMode}
                disabled={running}
              />
            </Field>

            {mode === "brute" ? (
              <>
                <Field label="字符集预设">
                  <div className="chips">
                    {PRESETS.map((preset) => (
                      <button
                        key={preset.value}
                        type="button"
                        className={`chip ${charset === preset.value ? "active" : ""}`}
                        onClick={() => setCharset(preset.value)}
                        disabled={running}
                      >
                        {preset.label}
                        <span className="chip-detail">{preset.detail}</span>
                      </button>
                    ))}
                  </div>
                </Field>

                <div className="form-grid-3">
                  <Field label="字符集定义">
                    <input
                      className="input mono"
                      value={charset}
                      onChange={(e) => setCharset(e.target.value)}
                      placeholder="lower+digits"
                      spellCheck={false}
                      disabled={running}
                    />
                  </Field>
                  <Field label="最小长度">
                    <input
                      className="input"
                      type="number"
                      min={1}
                      max={32}
                      value={minLen}
                      disabled={running}
                      onChange={(e) => {
                        const n = clampLen(e.target.value);
                        setMinLen(n);
                        if (n > maxLen) setMaxLen(n);
                      }}
                    />
                  </Field>
                  <Field label="最大长度">
                    <input
                      className="input"
                      type="number"
                      min={1}
                      max={32}
                      value={maxLen}
                      disabled={running}
                      onChange={(e) => {
                        const n = clampLen(e.target.value);
                        setMaxLen(n);
                        if (n < minLen) setMinLen(n);
                      }}
                    />
                  </Field>
                </div>

                <div className="space-callout">
                  <span className="space-icon">
                    <Icon name="cpu" size={15} />
                  </span>
                  <div>
                    <div className="space-label">候选空间</div>
                    <div className="space-value">
                      {space ? space.total_pretty : "计算中…"}
                    </div>
                  </div>
                  <span className="space-hint">
                    可用预设名或字面字符集，例如 <code>abc123</code>
                  </span>
                </div>
              </>
            ) : (
              <>
                <Field label="字典文件" hint="每行一个密码">
                  <div className="row">
                    <input
                      className="input mono grow"
                      value={dictionary}
                      onChange={(e) => setDictionary(e.target.value)}
                      placeholder="/path/to/wordlist.txt"
                      spellCheck={false}
                      disabled={running}
                    />
                    <Button
                      variant="ghost"
                      icon="folder"
                      disabled={running}
                      onClick={async () => {
                        const picked = await pickDictionary();
                        if (picked) setDictionary(picked);
                      }}
                    >
                      浏览
                    </Button>
                  </div>
                </Field>
                <div className="field-note">
                  <Icon name="info" size={13} />
                  <span>字典越大命中率越高。WinZip AES 强烈建议使用字典攻击。</span>
                </div>
              </>
            )}

            {isAes && mode === "brute" && (
              <Banner tone="warning">
                WinZip AES 使用 PBKDF2-HMAC-SHA1（1000 次迭代），暴力破解比 ZipCrypto
                慢约 1000 倍。建议切换到字典攻击。
              </Banner>
            )}

            <div className="config-footer">
              <Button
                icon="play"
                onClick={start}
                loading={starting}
                disabled={running || !path.trim()}
              >
                开始攻击
              </Button>
              {running ? (
                <span className="hint">
                  <span className="live-dot" />
                  攻击进行中，可随时停止
                </span>
              ) : (
                <span className="hint">密码只在本地计算，不联网。</span>
              )}
            </div>
          </div>
        </Card>

        <Card
          icon="zap"
          title="攻击进度"
          sub={
            activeInfo
              ? `${activeInfo.kind} · ${activeInfo.entry}`
              : "等待任务"
          }
          actions={
            running ? (
              <Button variant="danger" size="sm" icon="stop" onClick={cancel}>
                停止
              </Button>
            ) : null
          }
        >
          {!status ? (
            <div className="crack-idle">
              <div className="idle-orbit">
                <Icon name="key" size={24} />
              </div>
              <div className="idle-title">等待任务</div>
              <p>
                选择目标归档并检测加密类型，配置参数后开始攻击。
                所有计算都在本地完成。
              </p>
            </div>
          ) : (
            <div className="stack">
              <div className="big-progress">
                <div>
                  <div className="big-value">
                    {status.total ? percentText(pct) : humanCount(status.done)}
                  </div>
                  <div className="big-label">
                    {status.total ? "搜索空间进度" : "已尝试密码"}
                  </div>
                </div>
                <div className="big-side">
                  <div className="rate">
                    {humanCount(rate)}
                    <span>/s</span>
                  </div>
                  <div className="big-label">当前速度</div>
                </div>
              </div>

              <div
                className={`progress ${status.total ? "" : "indet"} ${
                  status.finished ? "done" : ""
                }`}
              >
                <div
                  className="progress-fill"
                  style={
                    status.total
                      ? { width: `${Math.min(100, Math.max(0, pct))}%` }
                      : undefined
                  }
                />
              </div>

              <div className="stats stats-4">
                <Stat label="已尝试" value={humanCount(status.done)} />
                <Stat
                  label="剩余"
                  value={
                    status.total
                      ? humanCount(Math.max(0, status.total - status.done))
                      : "—"
                  }
                />
                <Stat label="已用时" value={formatDuration(status.elapsed_secs)} />
                <Stat
                  label="预计剩余"
                  value={
                    status.finished || eta === null ? "—" : formatDuration(eta)
                  }
                />
              </div>

              {status.found && (
                <div className="found">
                  <div className="found-icon">
                    <Icon name="key" size={21} />
                  </div>
                  <div className="found-main">
                    <div className="found-label">密码已恢复</div>
                    <div className="found-pw">{status.found}</div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={copied ? "check" : "copy"}
                    onClick={copyPassword}
                  >
                    {copied ? "已复制" : "复制"}
                  </Button>
                </div>
              )}

              {status.finished && !status.found && (
                <Banner tone={status.cancelled ? "info" : "warning"}>
                  {status.cancelled ? "任务已停止。" : "搜索完成，未找到匹配密码。"}
                  可扩大字符集或长度范围，或改用更大的字典。
                </Banner>
              )}

              {!status.finished && status.cancelled && (
                <Banner tone="info">正在停止，等待工作线程退出…</Banner>
              )}
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
