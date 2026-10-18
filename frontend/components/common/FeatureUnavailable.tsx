import { Construction, ServerCog } from "lucide-react";
import type { ReactNode } from "react";
import { Card } from "./Card";

export interface EndpointDescriptor {
  method: string;
  path: string;
}

interface FeatureUnavailableProps {
  feature: string;
  summary: string;
  detail: string;
  backendSource?: string;
  endpoints?: EndpointDescriptor[];
  children?: ReactNode;
}

export function FeatureUnavailable({
  feature,
  summary,
  detail,
  backendSource,
  endpoints,
  children,
}: FeatureUnavailableProps) {
  return (
    <Card>
      <div className="card-body">
        <div className="unavailable">
          <span className="unavailable-badge">
            <Construction size={14} aria-hidden="true" />
            Endpoint not registered
          </span>

          <h2>{feature} is not available yet</h2>
          <p>{summary}</p>
          <p>{detail}</p>

          {backendSource ? (
            <p className="faint">
              Backend source exists at{" "}
              <span className="mono">{backendSource}</span> but its router is
              not registered in <span className="mono">backend/main.py</span>,
              so it is not reachable through the API.
            </p>
          ) : null}

          {endpoints && endpoints.length > 0 ? (
            <div className="endpoint-list">
              {endpoints.map((endpoint) => (
                <div
                  className="endpoint-item"
                  key={`${endpoint.method} ${endpoint.path}`}
                >
                  <span className="endpoint-method">{endpoint.method}</span>
                  {endpoint.path}
                </div>
              ))}
            </div>
          ) : null}

          <div className="notice warning">
            <ServerCog size={16} aria-hidden="true" style={{ marginTop: 1 }} />
            <span>
              This page deliberately shows no fabricated data. It will activate
              automatically once the corresponding backend route is registered
              and reachable.
            </span>
          </div>

          {children}
        </div>
      </div>
    </Card>
  );
}
