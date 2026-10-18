import { PageHeader } from "../components/layout/PageHeader";
import { FeatureUnavailable } from "../components/common/FeatureUnavailable";

export function Alerts() {
  return (
    <>
      <PageHeader
        title="Alerts"
        subtitle="Detections raised by the backend detection rules engine."
      />
      <FeatureUnavailable
        feature="Alerts"
        summary="There is no registered backend endpoint that returns raised alerts."
        detail="The detection API (backend/app/api/detections.py) depends on services/detection_service.py, which is currently empty, and neither router is registered in backend/main.py. The alert router (backend/app/api/alert.py) is also empty. Because of this, alerts cannot be retrieved yet."
        endpoints={[
          { method: "GET", path: "/api/v1/detections/health" },
          { method: "POST", path: "/api/v1/detections/run" },
        ]}
      />
    </>
  );
}
