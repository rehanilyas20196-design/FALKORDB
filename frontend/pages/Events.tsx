import { useMemo, useState } from "react";
import { Plus, RefreshCw } from "lucide-react";
import { PageHeader } from "../components/layout/PageHeader";
import { Card, CardBody, CardHeader } from "../components/common/Card";
import { Button } from "../components/common/Button";
import { Modal } from "../components/common/Modal";
import { EmptyState } from "../components/common/EmptyState";
import { ErrorMessage } from "../components/common/ErrorMessage";
import { useToast } from "../components/common/Toast";
import { EventFilter } from "../components/events/EventFilter";
import { EventTable } from "../components/events/EventTable";
import { EventDetails } from "../components/events/EventDetails";
import { CreateEventForm } from "../components/events/CreateEventForm";
import { useEvents } from "../hooks/useEvents";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import { DEFAULT_EVENT_LIMIT, DISCLAIMER, SEVERITY_LABELS } from "../utils/constants";
import { getErrorMessage } from "../utils/errors";
import type {
  CreateEventInput,
  EventSeverity,
  SecurityEvent,
} from "../types/event";

export function Events() {
  const toast = useToast();

  const [severity, setSeverity] = useState<EventSeverity | "">("");
  const [eventTypeInput, setEventTypeInput] = useState("");
  const debouncedEventType = useDebouncedValue(eventTypeInput, 400);

  const [createOpen, setCreateOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<SecurityEvent | null>(null);

  const { events, loading, error, refresh, createEvent, deleteEvent } = useEvents(
    {
      severity,
      event_type: debouncedEventType.trim(),
      limit: DEFAULT_EVENT_LIMIT,
    },
  );

  const filtersActive = severity !== "" || eventTypeInput.trim() !== "";

  const handleCreate = async (input: CreateEventInput) => {
    setSubmitting(true);
    try {
      const created = await createEvent(input);
      toast.push(
        "success",
        `Event "${created.event_type}" created.`,
        "Event ingested",
      );
      setCreateOpen(false);
    } catch (createError) {
      toast.push("error", getErrorMessage(createError), "Could not create event");
    } finally {
      setSubmitting(false);
    }
  };

  const confirmDelete = async () => {
    if (!pendingDelete) {
      return;
    }

    const target = pendingDelete;
    setDeletingId(target.event_id);

    try {
      await deleteEvent(target.event_id);
      toast.push(
        "success",
        `Event "${target.event_type}" deleted.`,
        "Event removed",
      );
      setPendingDelete(null);
      if (selected?.event_id === target.event_id) {
        setSelected(null);
      }
    } catch (deleteError) {
      toast.push("error", getErrorMessage(deleteError), "Could not delete event");
    } finally {
      setDeletingId(null);
    }
  };

  const resetFilters = () => {
    setSeverity("");
    setEventTypeInput("");
  };

  const currentFilterLabel = useMemo(() => {
    const parts: string[] = [];
    if (severity) {
      parts.push(`severity: ${SEVERITY_LABELS[severity]}`);
    }
    if (debouncedEventType.trim()) {
      parts.push(`type: ${debouncedEventType.trim()}`);
    }
    return parts.length > 0 ? parts.join(", ") : "all events";
  }, [severity, debouncedEventType]);

  return (
    <>
      <PageHeader
        title="Security Events"
        subtitle="Create, filter, inspect, and delete security events stored by the backend event API."
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
            <Button
              variant="primary"
              icon={<Plus size={16} aria-hidden="true" />}
              onClick={() => setCreateOpen(true)}
            >
              New event
            </Button>
          </>
        }
      />

      <div className="notice warning" style={{ marginBottom: 20 }}>
        {DISCLAIMER}
      </div>

      <Card>
        <CardHeader
          title="Filters"
          subtitle={`Showing ${currentFilterLabel}`}
          action={
            filtersActive ? (
              <Button variant="ghost" size="sm" onClick={resetFilters}>
                Clear filters
              </Button>
            ) : null
          }
        />
        <CardBody>
          <EventFilter
            severity={severity}
            eventType={eventTypeInput}
            loading={loading}
            resultCount={events.length}
            onSeverityChange={setSeverity}
            onEventTypeChange={setEventTypeInput}
            onReset={resetFilters}
          />
        </CardBody>
      </Card>

      <div style={{ marginTop: 20 }}>
        <Card>
          <CardBody flush>
            {error ? (
              <div style={{ padding: 20 }}>
                <ErrorMessage
                  title="Could not load events"
                  message={error}
                  onRetry={refresh}
                />
              </div>
            ) : loading ? (
              <div className="state-block">
                <span className="spinner" aria-hidden="true" />
                <span className="muted">Loading events…</span>
              </div>
            ) : events.length === 0 ? (
              <EmptyState
                title={filtersActive ? "No matching events" : "No events yet"}
                description={
                  filtersActive
                    ? "Try adjusting or clearing the filters."
                    : "Create the first security event to get started."
                }
                action={
                  filtersActive ? (
                    <Button variant="secondary" size="sm" onClick={resetFilters}>
                      Clear filters
                    </Button>
                  ) : (
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => setCreateOpen(true)}
                    >
                      New event
                    </Button>
                  )
                }
              />
            ) : (
              <EventTable
                events={events}
                deletingId={deletingId}
                onSelect={setSelected}
                onDelete={setPendingDelete}
              />
            )}
          </CardBody>
        </Card>
      </div>

      <Modal
        open={createOpen}
        title="Create security event"
        onClose={() => setCreateOpen(false)}
        maxWidth={720}
      >
        <CreateEventForm
          submitting={submitting}
          onSubmit={handleCreate}
          onCancel={() => setCreateOpen(false)}
        />
      </Modal>

      <Modal
        open={selected !== null}
        title="Event details"
        onClose={() => setSelected(null)}
        footer={
          <Button variant="secondary" onClick={() => setSelected(null)}>
            Close
          </Button>
        }
      >
        {selected ? <EventDetails event={selected} /> : null}
      </Modal>

      <Modal
        open={pendingDelete !== null}
        title="Delete event"
        onClose={() => setPendingDelete(null)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setPendingDelete(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={deletingId !== null}
              onClick={confirmDelete}
            >
              Delete
            </Button>
          </>
        }
      >
        {pendingDelete ? (
          <p className="muted">
            Permanently delete the event{" "}
            <strong>{pendingDelete.event_type}</strong> (
            <span className="mono">{pendingDelete.event_id}</span>)? This action
            cannot be undone.
          </p>
        ) : null}
      </Modal>
    </>
  );
}
