// Small shared presentational components.
import { useCallback, useEffect, useRef, useState } from "react";
import type { DragEvent } from "react";
import type { FindingLevel, MitreRef } from "@/models";

export function LevelBadge({ level }: { level: FindingLevel }) {
  return <span className={`badge badge-${level}`}>{level}</span>;
}

/** Render a technique string (e.g. "T1055·T1620") as ATT&CK links. */
export function MitreLinks({
  technique,
  refs,
}: {
  technique?: string;
  refs?: MitreRef[];
}) {
  const list: MitreRef[] =
    refs ??
    (technique
      ? technique
          .split(/[·,]/)
          .map((t) => t.trim())
          .filter(Boolean)
          .map((id) => {
            const parts = id.split(".");
            const url =
              parts.length === 2
                ? `https://attack.mitre.org/techniques/${parts[0]}/${parts[1]}/`
                : `https://attack.mitre.org/techniques/${parts[0]}/`;
            return { id, url };
          })
      : []);
  if (!list.length) return null;
  return (
    <span className="mitre">
      {list.map((m) => (
        <a
          key={m.id}
          href={m.url}
          target="_blank"
          rel="noreferrer"
          title={[m.name, m.tactic].filter(Boolean).join(" — ")}
        >
          {m.id}
        </a>
      ))}
    </span>
  );
}

export function FileDropZone({
  onFiles,
  label = "Drop Volatility CSV exports here",
}: {
  onFiles: (files: { name: string; text: string }[]) => void;
  label?: string;
}) {
  const [hover, setHover] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const read = useCallback(
    async (fileList: FileList) => {
      const files = await Promise.all(
        Array.from(fileList).map(
          (f) =>
            new Promise<{ name: string; text: string }>((resolve, reject) => {
              const r = new FileReader();
              r.onload = () => resolve({ name: f.name, text: String(r.result) });
              r.onerror = () => reject(r.error);
              r.readAsText(f);
            })
        )
      );
      onFiles(files);
    },
    [onFiles]
  );

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setHover(false);
    if (e.dataTransfer?.files?.length) void read(e.dataTransfer.files);
  };

  return (
    <div
      className={`dropzone${hover ? " dropzone-hover" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        setHover(true);
      }}
      onDragLeave={() => setHover(false)}
      onDrop={onDrop}
      onClick={() => inputRef.current?.click()}
      role="button"
      tabIndex={0}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".csv,text/csv"
        multiple
        hidden
        onChange={(e) => {
          if (e.target.files?.length) void read(e.target.files);
          e.target.value = "";
        }}
      />
      <span className="dropzone-icon">⬇</span>
      <span>{label}</span>
      <small>or click to browse — parsing happens locally, nothing is uploaded</small>
    </div>
  );
}

export interface ToastMsg {
  id: number;
  text: string;
  tone: "ok" | "warn" | "err";
}

let toastSeq = 0;
const listeners = new Set<(t: ToastMsg) => void>();

export function pushToast(text: string, tone: ToastMsg["tone"] = "ok"): void {
  const msg = { id: ++toastSeq, text, tone };
  listeners.forEach((l) => l(msg));
}

export function ToastHost() {
  const [toasts, setToasts] = useState<ToastMsg[]>([]);
  useEffect(() => {
    const onMsg = (t: ToastMsg) => {
      setToasts((prev) => [...prev, t]);
      setTimeout(() => setToasts((prev) => prev.filter((x) => x.id !== t.id)), 3500);
    };
    listeners.add(onMsg);
    return () => {
      listeners.delete(onMsg);
    };
  }, []);
  return (
    <div className="toast-host">
      {toasts.map((t) => (
        <div key={t.id} className={`toast toast-${t.tone}`}>
          {t.text}
        </div>
      ))}
    </div>
  );
}

/** Clipboard copy with execCommand fallback for file:// / sandboxed contexts. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to legacy path */
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;opacity:0;";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try {
      ta.setSelectionRange(0, text.length);
    } catch {
      /* ignore */
    }
    const ok = document.execCommand && document.execCommand("copy");
    document.body.removeChild(ta);
    return !!ok;
  } catch {
    return false;
  }
}
<<<<<<< HEAD

export { DataTable, type Column, type SortState } from "./DataTable";
=======
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
