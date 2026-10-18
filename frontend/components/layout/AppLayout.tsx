import { useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Slidebar } from "./Slidebar";
import { Topbar } from "./Topbar";

export function AppLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname]);

  return (
    <div className="app-shell">
      <Slidebar open={sidebarOpen} onNavigate={() => setSidebarOpen(false)} />

      {sidebarOpen ? (
        <button
          type="button"
          className="sidebar-backdrop"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      ) : null}

      <div className="app-main-wrapper">
        <Topbar onMenuClick={() => setSidebarOpen((open) => !open)} />
        <main className="app-main">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
