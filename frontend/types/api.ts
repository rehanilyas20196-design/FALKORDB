export interface HealthResponse {
  status: string;
  application: string;
  version: string;
  timestamp: string;
}

export interface ReadinessResponse {
  status: string;
  application: string;
  database: string;
  timestamp: string;
}

export interface ApiRouteInfo {
  path: string;
  methods: string[];
}

export interface ApiInfo {
  name: string;
  version: string;
  api_prefix: string;
  documentation: string;
  openapi: string;
  endpoints: Record<string, string>;
  modules: string[];
  registered_routes: ApiRouteInfo[];
}

export interface ApiErrorBody {
  detail?: unknown;
  message?: string;
}
