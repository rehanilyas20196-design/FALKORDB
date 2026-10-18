import { API_PREFIX } from "../utils/constants";

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, "");
}

const RAW_BASE_URL =
  (import.meta.env.VITE_API_URL as string | undefined)?.trim() ||
  (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() ||
  "https://falkordb-tfuk.onrender.com";

export const API_BASE_URL = normalizeBaseUrl(RAW_BASE_URL);

function apiUrl(path: string): string {
  if (path.startsWith("http://") || path.startsWith("https://")) {
    return path;
  }

  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${API_BASE_URL}${normalizedPath}`;
}

function apiPrefixUrl(path: string): string {
  return apiUrl(`${API_PREFIX}${path.startsWith("/") ? path : `/${path}`}`);
}

function redactBaseUrl(baseUrl: string): string {
  return normalizeBaseUrl(baseUrl);
}

function parseDetail(detail: unknown): string | null {
  if (detail === null || detail === undefined) {
    return null;
  }

  if (typeof detail === "string") {
    return detail;
  }

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (item && typeof item === "object" && "msg" in item) {
          const record = item as Record<string, unknown>;
          const location = Array.isArray(record.loc)
            ? record.loc.filter((part) => part !== "body").join(".")
            : "";
          const message = String(record.msg ?? "Invalid value");
          return location ? `${location}: ${message}` : message;
        }

        return typeof item === "string" ? item : JSON.stringify(item);
      })
      .filter(Boolean);

    return messages.length > 0 ? messages.join(", ") : null;
  }

  if (typeof detail === "object" && "message" in detail) {
    const record = detail as Record<string, unknown>;
    if (typeof record.message === "string") {
      return record.message;
    }
  }

  try {
    return JSON.stringify(detail);
  } catch {
    return String(detail);
  }
}

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(
    message: string,
    status: number,
    detail: unknown = null,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }

  get isOffline(): boolean {
    return this.status === 0;
  }
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
  useApiPrefix?: boolean;
}

async function readBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";

  if (response.status === 204) {
    return null;
  }

  if (contentType.includes("application/json")) {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  try {
    const text = await response.text();
    return text.length > 0 ? text : null;
  } catch {
    return null;
  }
}

export async function apiRequest<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const { signal, useApiPrefix = true } = options;

  const url = useApiPrefix ? apiPrefixUrl(path) : apiUrl(path);

  const headers: Record<string, string> = {
    Accept: "application/json",
  };

  let body: string | undefined;

  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }

  let response: Response;

  try {
    response = await fetch(url, {
      method: options.method ?? "GET",
      headers,
      body,
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }

    throw new ApiError(
      `Unable to reach the backend at ${redactBaseUrl(API_BASE_URL)}. ` +
        "Confirm the API server is running and VITE_API_BASE_URL is correct.",
      0,
      null,
    );
  }

  const payload = await readBody(response);

  if (!response.ok) {
    const detail =
      payload && typeof payload === "object" && "detail" in payload
        ? (payload as { detail: unknown }).detail
        : payload;

    const message =
      parseDetail(detail) ??
      `Request failed with status ${response.status} ${response.statusText}.`;

    throw new ApiError(message, response.status, detail);
  }

  return payload as T;
}

export function buildQueryString(
  params: Record<string, string | number | undefined | null>,
): string {
  const search = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    search.set(key, String(value));
  }

  const query = search.toString();
  return query.length > 0 ? `?${query}` : "";
}
