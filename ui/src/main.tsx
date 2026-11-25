import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
// Self-hosted fonts, bundled into dist/ui so the UI makes no network call off the machine.
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./theme.css";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
