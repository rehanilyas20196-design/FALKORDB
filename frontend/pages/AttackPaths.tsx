import { PageHeader } from "../components/layout/PageHeader";
import { FeatureUnavailable } from "../components/common/FeatureUnavailable";

export function AttackPaths() {
  return (
    <>
      <PageHeader
        title="Attack Paths"
        subtitle="Graph-based analysis of lateral movement and access paths."
      />
      <FeatureUnavailable
        feature="Attack Paths"
        summary="No registered backend endpoint exposes attack path or graph analysis results."
        detail="backend/app/api/graph.py defines a graph router and backend/app/services/attack_path_service.py implements path analysis, but neither is registered in backend/main.py. The running API therefore cannot return graph or attack path data."
        backendSource="backend/app/api/graph.py"
        endpoints={[
          { method: "GET", path: "/api/v1/graph/health" },
          { method: "GET", path: "/api/v1/graph/overview" },
          { method: "GET", path: "/api/v1/graph/" },
        ]}
      />
    </>
  );
}
