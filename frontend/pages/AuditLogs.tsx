import { PageHeader } from "../components/layout/PageHeader";
import { FeatureUnavailable } from "../components/common/FeatureUnavailable";

export function AuditLogs() {
  return (
    <>
      <PageHeader
        title="Audit Logs"
        subtitle="Immutable record of security-relevant actions and system activity."
      />
      <FeatureUnavailable
        feature="Audit Logs"
        summary="The audit service exists in source but no audit route is registered with the API."
        detail="backend/app/services/audit_service.py implements audit logging, but backend/main.py does not register any audit router, so audit records cannot be listed from the frontend yet."
        backendSource="backend/app/services/audit_service.py"
      />
    </>
  );
}
