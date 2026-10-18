import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  Bot,
  Plus,
  Radio,
  RefreshCw,
  ServerCog,
} from "lucide-react";
import { PageHeader } from "../components/layout/PageHeader";
import { StatCard } from "../components/dashboard/StatCard";
import { SeverityCard } from "../components/dashboard/SeverityCard";
import { EventTimeLine } from "../components/dashboard/EventTimeLine";
import { RecentAlert } from "../components/dashboard/RecentAlert";
import { Card, CardBody, CardHeader } from "../components/common/Card";
import { Badge } from "../components/common/Badge";
import { Button } from "../components/common/Button";
import { EmptyState } from "../components/common/EmptyState";
import { ErrorMessage } from "../components/common/ErrorMessage";
import { useDashboard } from "../hooks/useDashboard";
import { SEVERITY_ORDER } from "../utils/constants";
import { formatDateTime } from "../utils/formatDate";

export function Dashboard() {
  const {
    stats,
    recentEvents,
    alertEvents,
    loading,
    error,
    refresh,
    systemHealth,
    systemHealthError,
    assistantHealth,
    assistantHealthError,
  } = useDashboard();

  return (
    <>
      <PageHeader
        title="Security Overview"
        subtitle="Live operational summary derived from ingested security events and the backend system endpoints."
        actions={
          <>
            <Button
              variant="secondary"
              icon={<RefreshCw size={16} aria-hidden="true" />}
              onClick={refresh}
              loading={loading}
            >
              Refresh
            </Button>
            <Link to="/events">
              <Button variant="primary" icon={<Plus size={16} aria-hidden="true" />}>
                New event
              </Button>
            </Link>
          </>
        }
      />

      {error ? (
        <div style={{ marginBottom: 20 }}>
          <ErrorMessage
            title="Could not load events"
            message={error}
            onRetry={refresh}
          />
        </div>
      ) : null}

      <div className="stat-grid" style={{ marginBottom: 20 }}>
        <StatCard
          label="Total events"
          value={loading ? "—" : stats.total}
          hint="Ingested security events"
          icon={<Activity size={20} />}
        />
        <StatCard
          label="High priority"
          value={loading ? "—" : stats.highPriority}
          hint="Critical + high severity"
          tone="danger"
          icon={<AlertTriangle size={20} />}
        />
        <StatCard
          label="Last 24 hours"
          value={loading ? "—" : stats.last24h}
          hint="Events in the last day"
          tone="warning"
          icon={<Radio size={20} />}
        />
        <StatCard
          label="Unique sources"
          value={loading ? "—" : stats.uniqueSources}
          hint="Distinct reporting sources"
          tone="accent"
          icon={<ServerCog size={20} />}
        />
      </div>

      <Card>
        <CardHeader title="Severity distribution" />
        <CardBody>
          <div className="severity-grid">
            {SEVERITY_ORDER.map((severity) => (
              <SeverityCard
                key={severity}
                severity={severity}
                count={stats.bySeverity[severity]}
              />
            ))}
          </div>
        </CardBody>
      </Card>

      <div className="grid-2" style={{ marginTop: 20 }}>
        <Card>
          <CardHeader
            title="Recent events"
            action={
              <Link className="faint" to="/events">
                View all
              </Link>
            }
          />
          <CardBody flush>
            {loading ? (
              <div className="state-block">
                <span className="spinner" aria-hidden="true" />
              </div>
            ) : recentEvents.length === 0 ? (
              <EmptyState
                title="No events yet"
                description="Create or ingest security events to populate the dashboard."
                action={
                  <Link to="/events">
                    <Button variant="secondary" size="sm">
                      Go to events
                    </Button>
                  </Link>
                }
              />
            ) : (
              <EventTimeLine events={recentEvents} />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Priority alerts" />
          <CardBody flush>
            {loading ? (
              <div className="state-block">
                <span className="spinner" aria-hidden="true" />
              </div>
            ) : (
              <RecentAlert events={alertEvents} />
            )}
          </CardBody>
        </Card>
      </div>

      <div className="grid-2" style={{ marginTop: 20 }}>
        <Card>
          <CardHeader
            title="System status"
            action={
              systemHealth ? (
                <Badge variant="low">{systemHealth.status}</Badge>
              ) : systemHealthError ? (
                <Badge variant="critical">unreachable</Badge>
              ) : (
                <Badge variant="neutral">checking</Badge>
              )
            }
          />
          <CardBody>
            {systemHealthError ? (
              <ErrorMessage
                title="Backend API unreachable"
                message={systemHealthError}
              />
            ) : systemHealth ? (
              <div className="detail-list">
                <div className="detail-row">
                  <div className="detail-key">Application</div>
                  <div className="detail-value">{systemHealth.application}</div>
                </div>
                <div className="detail-row">
                  <div className="detail-key">Version</div>
                  <div className="detail-value">
                    <span className="mono">{systemHealth.version}</span>
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-key">Reported at</div>
                  <div className="detail-value">
                    {formatDateTime(systemHealth.timestamp)}
                  </div>
                </div>
              </div>
            ) : (
              <div className="row">
                <span className="spinner sm" aria-hidden="true" />
                <span className="muted">Contacting backend…</span>
              </div>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title={
              <span className="row" style={{ gap: 8 }}>
                <Bot size={16} aria-hidden="true" /> AI assistant
              </span>
            }
            action={
              assistantHealth ? (
                <Badge
                  variant={assistantHealth.gemini_configured ? "low" : "medium"}
                >
                  {assistantHealth.gemini_configured ? "live" : "fallback"}
                </Badge>
              ) : (
                <Badge variant="neutral">unknown</Badge>
              )
            }
          />
          <CardBody>
            {assistantHealthError ? (
              <ErrorMessage
                title="Assistant service unreachable"
                message={assistantHealthError}
              />
            ) : assistantHealth ? (
              <div className="detail-list">
                <div className="detail-row">
                  <div className="detail-key">Model</div>
                  <div className="detail-value">
                    <span className="mono">{assistantHealth.model}</span>
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-key">Gemini configured</div>
                  <div className="detail-value">
                    {assistantHealth.gemini_configured ? "Yes" : "No"}
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-key">Status</div>
                  <div className="detail-value">
                    {assistantHealth.status}
                  </div>
                </div>
              </div>
            ) : (
              <div className="row">
                <span className="spinner sm" aria-hidden="true" />
                <span className="muted">Contacting assistant…</span>
              </div>
            )}
            <div style={{ marginTop: 16 }}>
              <Link to="/assistant">
                <Button variant="secondary" size="sm">
                  Open assistant
                </Button>
              </Link>
            </div>
          </CardBody>
        </Card>
      </div>
    </>
  );
}
