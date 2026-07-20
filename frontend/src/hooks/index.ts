// React Query hooks over the typed API client. These power the optional
// backend-connected features (live Volatility runs, page-cache dumps). The app
// also works fully offline by ingesting CSVs directly, so these are additive.
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "@/api/client";

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    retry: false,
    refetchInterval: 30_000,
  });
}

export function useImages(enabled = true) {
  return useQuery({
    queryKey: ["images"],
    queryFn: api.images,
    enabled,
    retry: false,
  });
}

export function usePlugins(enabled = true) {
  return useQuery({
    queryKey: ["plugins"],
    queryFn: api.plugins,
    enabled,
    retry: false,
    staleTime: Infinity,
  });
}

export function useActivity(enabled = true) {
  return useQuery({
    queryKey: ["activity"],
    queryFn: () => api.activity(200),
    enabled,
    retry: false,
    refetchInterval: enabled ? 2500 : false,
  });
}

export function useRunPlugin() {
  return useMutation({
    mutationFn: api.run,
  });
}

export function useDetect() {
  return useMutation({
    mutationFn: api.detect,
  });
}

export function useDumpInode() {
  return useMutation({
    mutationFn: api.dumpInode,
  });
}

export function useRecoverFs() {
  return useMutation({
    mutationFn: api.recoverFs,
  });
}

/** Poll a job until it reaches a terminal state. */
export function useJob(id: string | null) {
  return useQuery({
    queryKey: ["job", id],
    queryFn: () => api.job(id as string),
    enabled: !!id,
    refetchInterval: (query) => {
      const state = query.state.data?.state;
      return state === "succeeded" || state === "failed" ? false : 1500;
    },
  });
}

export function useInvalidateImages() {
  const qc = useQueryClient();
  return () => qc.invalidateQueries({ queryKey: ["images"] });
}
