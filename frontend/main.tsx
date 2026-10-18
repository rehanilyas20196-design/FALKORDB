import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { ToastProvider } from "./components/common/Toast";
import "./index.css";

const container = document.getElementById("root");

if (container === null) {
  throw new Error('Root element with id "root" was not found.');
}

createRoot(container).render(
  <StrictMode>
    <ToastProvider>
      <App />
    </ToastProvider>
  </StrictMode>,
);
