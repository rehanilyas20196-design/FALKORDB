import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AppLayout } from "./components/layout/AppLayout";
import { Dashboard } from "./pages/Dashboard";
import { Events } from "./pages/Events";
import { Alerts } from "./pages/Alerts";
import { Investigations } from "./pages/Investigations";
import { AttackPaths } from "./pages/AttackPaths";
import { Assistant } from "./pages/Assistant";
import { AuditLogs } from "./pages/AuditLogs";
import { NotFound } from "./pages/NotFound";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/events" element={<Events />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/attack-paths" element={<AttackPaths />} />
          <Route path="/assistant" element={<Assistant />} />
          <Route path="/audit-logs" element={<AuditLogs />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
