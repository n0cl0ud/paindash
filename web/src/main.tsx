import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { ApiError, SessionExpiredError } from "./api/client";
import App from "./App";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The selected env is kept fresh by the SSE stream; other envs refetch
      // in the background when they are switched to after this delay.
      staleTime: 30_000,
      retry: (count, error) =>
        count < 2 &&
        !(error instanceof SessionExpiredError) &&
        !(error instanceof ApiError && error.status < 500),
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
