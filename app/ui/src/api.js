// Thin wrappers around Tauri IPC + native dialogs.
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open, save } from "@tauri-apps/plugin-dialog";

export { invoke };
export { getCurrentWebview };

const ARCHIVE_EXTS = ["zip", "7z", "tar", "gz", "tgz", "xz", "bz2"];

function firstPath(result) {
  if (Array.isArray(result)) return result[0] ?? null;
  return typeof result === "string" ? result : null;
}

export async function pickArchive() {
  return firstPath(
    await open({
      multiple: false,
      directory: false,
      title: "选择归档文件",
      filters: [{ name: "归档文件", extensions: ARCHIVE_EXTS }],
    })
  );
}

export async function pickFiles() {
  const result = await open({
    multiple: true,
    directory: false,
    title: "选择要压缩的文件",
  });
  if (Array.isArray(result)) return result;
  return typeof result === "string" ? [result] : [];
}

export async function pickDirectory(title = "选择目录") {
  return firstPath(await open({ multiple: false, directory: true, title }));
}

export async function pickDictionary() {
  return firstPath(
    await open({
      multiple: false,
      directory: false,
      title: "选择字典文件",
      filters: [
        { name: "密码字典", extensions: ["txt", "dic", "dict", "lst", "wordlist"] },
      ],
    })
  );
}

export async function pickZipSave(defaultPath = "archive.zip") {
  return firstPath(
    await save({
      title: "保存 ZIP 归档",
      defaultPath,
      filters: [{ name: "ZIP 归档", extensions: ["zip"] }],
    })
  );
}
