import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HashRouter, Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { ProcessGraphPage } from "@/pages/ProcessGraphPage";
import { FilesModulesPage } from "@/pages/FilesModulesPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <HashRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<ProcessGraphPage />} />
            <Route path="files" element={<FilesModulesPage />} />
          </Route>
        </Routes>
      </HashRouter>
    </QueryClientProvider>
  );
}
