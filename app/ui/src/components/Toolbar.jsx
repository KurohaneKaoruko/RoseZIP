import React, { useCallback, useEffect, useRef, useState } from "react";
import { invoke, pickArchive } from "../api";
import { Icon } from "../icons";
import { Badge } from "../ui";

/**
 * 紧凑工具栏：图标+文字小按钮，参考 7-Zip / Bandizip。
 * 所有动作集中在这一个条上。
 */
export default function Toolbar({ hasArchive, busy, onOpen, onExtract, onCompress, onCrack, onBench }) {
  return (
    <div className="toolbar" role="toolbar" aria-label="主工具栏">
      <button className="tb-btn" onClick={onOpen} title="打开归档 (Ctrl+O)" disabled={busy}>
        <Icon name="folder" size={15} />
        <span>打开</span>
      </button>
      <span className="tb-sep" />
      <button className="tb-btn" onClick={onExtract} title="解压到…" disabled={!hasArchive || busy}>
        <Icon name="download" size={15} />
        <span>解压</span>
      </button>
      <button className="tb-btn" onClick={onCompress} title="新建压缩包" disabled={busy}>
        <Icon name="plus" size={15} />
        <span>压缩</span>
      </button>
      <span className="tb-sep" />
      <button
        className="tb-btn tb-accent"
        onClick={onCrack}
        title="找回密码"
        disabled={!hasArchive || busy}
      >
        <Icon name="key" size={15} />
        <span>密码找回</span>
      </button>
      <span className="tb-flex" />
      <button className="tb-btn tb-icon-only" onClick={onBench} title="性能测试">
        <Icon name="gauge" size={15} />
      </button>
    </div>
  );
}

/** 地址栏：当前归档 + 格式/加密徽章。 */
export function AddressBar({ path, view, onOpen }) {
  const enc = view?.encryption;
  const is7z = view?.format === "SevenZ";
  return (
    <div className="addr-bar">
      <span className="addr-icon">
        <Icon name="archive" size={14} />
      </span>
      {view ? (
        <>
          <span className="addr-path mono" title={path}>
            {path}
          </span>
          <span className="addr-badges">
            <Badge tone="neutral">{formatName(view.format)}</Badge>
            {enc ? (
              <Badge tone={enc.includes("AES") ? "violet" : "amber"} icon="lock">
                {enc.includes("ZipCrypto")
                  ? "ZipCrypto"
                  : is7z
                    ? "7z AES"
                    : enc.includes("AES")
                      ? "WinZip AES"
                      : "加密"}
              </Badge>
            ) : null}
          </span>
        </>
      ) : (
        <span className="addr-hint" onClick={onOpen}>
          打开一个归档开始 · ZIP / 7Z / TAR / GZ / XZ / BZ2
        </span>
      )}
    </div>
  );
}

export function formatName(f) {
  return { Zip: "ZIP", SevenZ: "7Z", Tar: "TAR", Gz: "GZ", Xz: "XZ", Bz2: "BZ2" }[f] || f;
}
