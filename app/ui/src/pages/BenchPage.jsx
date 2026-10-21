import React, { useState } from "react";
import { invoke } from "../api";
import { humanCount } from "../format";
import { Icon } from "../icons";
import { Badge, Button, Card, PageHead, useToast } from "../ui";

export default function BenchPage() {
  const notify = useToast();
  const [bench, setBench] = useState(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try {
      const result = await invoke("bench_speed");
      setBench(result);
      notify("success", "基准测试完成");
    } catch (e) {
      notify("error", `基准测试失败：${e}`);
    } finally {
      setBusy(false);
    }
  }

  const zipM = bench ? bench.zipcrypto_per_sec / 1e6 : null;
  const perThreadM = bench ? bench.zipcrypto_per_sec / bench.threads / 1e6 : null;

  return (
    <>
      <PageHead
        kicker="BENCHMARK"
        title="性能基准"
        desc="测量本机 CPU 校验加密密码的吞吐量。数字越高，穷举搜索越快。"
      >
        <Badge tone="green" icon="cpu">
          本地 CPU
        </Badge>
      </PageHead>

      <Card className="bench-card">
        <div className="bench-hero">
          <div>
            <div className="bench-kicker">ZipCrypto · 密码校验速度</div>
            <div className={`bench-number ${zipM === null ? "muted" : ""}`}>
              {zipM === null ? "—" : zipM.toFixed(2)}
              {zipM !== null && <span>M</span>}
              {zipM !== null && <small>/s</small>}
            </div>
            <div className="bench-sub">
              {bench
                ? `${bench.threads} 线程并行 · 单线程 ${perThreadM.toFixed(2)}M/s`
                : "点击右侧按钮开始，约需 2–3 秒"}
            </div>
          </div>
          <Button icon="zap" onClick={run} loading={busy}>
            {bench ? "重新测试" : "开始测试"}
          </Button>
        </div>

        <div className="bench-split">
          <div className="bench-track">
            <div className="bench-track-head">
              <span>
                <Icon name="zap" size={13} /> ZipCrypto
              </span>
              <span className="mono">
                {bench ? `${humanCount(bench.zipcrypto_per_sec)}/s` : "—"}
              </span>
            </div>
            <div className="mini-track">
              <div
                className="mini-fill"
                style={{ width: bench ? "100%" : "0%" }}
              />
            </div>
            <div className="bench-note">
              直接校验 12 字节加密头，无密钥派生，可全速穷举。
            </div>
          </div>

          <div className="bench-track">
            <div className="bench-track-head">
              <span>
                <Icon name="shield" size={13} /> WinZip AES
              </span>
              <span className="mono">
                {bench ? `${humanCount(bench.aes_per_sec)}/s` : "—"}
              </span>
            </div>
            <div className="mini-track">
              <div
                className="mini-fill aes"
                style={{ width: bench ? "1.2%" : "0%" }}
              />
            </div>
            <div className="bench-note">
              PBKDF2-HMAC-SHA1 迭代 1000 次，约比 ZipCrypto 慢 1000 倍。
            </div>
          </div>
        </div>
      </Card>

      <div className="tip-grid">
        <div className="tip-card">
          <span className="tip-icon">
            <Icon name="cpu" size={16} />
          </span>
          <h4>多线程并行</h4>
          <p>自动使用全部逻辑核心；每个线程独立分片搜索空间，互不重复。</p>
        </div>
        <div className="tip-card">
          <span className="tip-icon">
            <Icon name="zap" size={16} />
          </span>
          <h4>热路径优化</h4>
          <p>ZipCrypto 前缀密钥缓存 + 内联校验，只对通过头部检查的候选做完整验证。</p>
        </div>
        <div className="tip-card">
          <span className="tip-icon">
            <Icon name="alert" size={16} />
          </span>
          <h4>现实预期</h4>
          <p>8 位以上混合字符集的搜索空间极大；优先尝试字典、常见口令变体与掩码。</p>
        </div>
      </div>
    </>
  );
}
