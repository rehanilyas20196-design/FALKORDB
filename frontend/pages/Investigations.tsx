import { PageHeader } from "../components/layout/PageHeader";
import { FeatureUnavailable } from "../components/common/FeatureUnavailable";

export function Investigations() {
  return (
    <>
      <PageHeader
        title="Investigations"
        subtitle="Case management for security investigations."
      />
      <FeatureUnavailable
        feature="Investigations"
        summary="The cases API exists in source but is not registered with the running FastAPI application."
        detail="backend/app/api/cases.py defines an in-memory cases router, but backend/main.py only registers the assistant and event routers. Until the cases router is registered, these endpoints return 404 and no case data is available."
        backendSource="backend/app/api/cases.py"
        endpoints={[
          { method: "GET", path: "/api/v1/cases/health" },
          { method: "POST", path: "/api/v1/cases" },
          { method: "GET", path: "/api/v1/cases" },
          { method: "GET", path: "/api/v1/cases/{case_id}" },
          { method: "PATCH", path: "/api/v1/cases/{case_id}" },
        ]}
      />
    </>
  );
}
