// Typed fetch wrapper for the ProcTree backend API.
// Kept dependency-free; React Query hooks wrap these calls.

export interface HealthResponse {
  status: string;
  volatility_available: boolean;
  volatility_version: string | null;
  image_dir: string;
  plugins_allowed: number;
}

export interface ImageInfo {
  name: string;
  size_bytes: number;
  modified: string;
}

export interface PluginInfo {
  name: string;
  os: string;
  category: string;
  produces_table: boolean;
}

export interface ActivityEvent {
  id: number;
  ts: number;
  kind: string;
  status: "ok" | "empty" | "error";
  argv: string[];
  duration_ms: number;
  returncode: number | null;
  plugin: string | null;
  image: string | null;
  rows: number | null;
  stdout_bytes: number;
  stderr_bytes: number;
  stderr: string | null;
  message: string | null;
}

export interface RunResponse {
  plugin: string;
  rows: number;
  renderer: string;
  csv: string;
  stderr: string | null;
}

export interface BackendFinding {
  level: "alert" | "warn" | "info";
  rule: string;
  technique: string | null;
  target: string;
  detail: string;
}

export interface DetectResponse {
  findings: BackendFinding[];
  counts: Record<string, number>;
}

export interface ArtifactMeta {
  token: string;
  filename: string;
  size_bytes: number;
  sha256: string;
}

export type JobState = "pending" | "running" | "succeeded" | "failed";

export interface JobResponse {
  id: string;
  state: JobState;
  kind: string;
  created: string;
  finished: string | null;
  error: string | null;
  artifacts: ArtifactMeta[];
}

export interface ApiErrorBody {
  code: string;
  message: string;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const BASE = "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(init?.headers ?? {}),
      },
    });
  } catch (e) {
    throw new ApiError(
      `Network error reaching backend: ${(e as Error).message}`,
      0,
      "network_error"
    );
  }
  if (!res.ok) {
    let code = "http_error";
    let message = `Request failed (${res.status})`;
    try {
      const body = (await res.json()) as { error?: ApiErrorBody };
      if (body.error) {
        code = body.error.code;
        message = body.error.message;
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(message, res.status, code);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  health: () => request<HealthResponse>("/health"),

  images: () => request<{ images: ImageInfo[] }>("/images").then((r) => r.images),

  plugins: () =>
    request<{ plugins: PluginInfo[] }>("/plugins").then((r) => r.plugins),

  activity: (limit = 200) =>
    request<{ events: ActivityEvent[] }>(`/activity?limit=${limit}`).then((r) => r.events),

  clearActivity: () =>
    request<{ cleared: number }>("/activity", { method: "DELETE" }),

  run: (body: {
    image: string;
    plugin: string;
    options?: Record<string, string | null>;
    renderer?: string;
  }) =>
    request<RunResponse>("/plugins/run", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  detect: (body: {
    os: string;
    records: unknown[];
    pagecache: unknown[];
    modules: unknown[];
  }) =>
    request<DetectResponse>("/plugins/detect", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  dumpInode: (body: { image: string; inode: string }) =>
    request<JobResponse>("/jobs/inode", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  recoverFs: (body: { image: string }) =>
    request<JobResponse>("/jobs/recoverfs", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  job: (id: string) => request<JobResponse>(`/jobs/${id}`),

  downloadUrl: (token: string) => `${BASE}/dumps/download/${token}`,
};
