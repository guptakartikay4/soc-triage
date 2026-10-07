import { useState, useEffect, useCallback, useRef } from "react";

interface UseResourceResult<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  refetch: () => Promise<void>;
}

export function useResource<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  dependencies: any[] = []
): UseResourceResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  
  const fetcherRef = useRef(fetcher);
  
  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  const fetchData = useCallback(async (isRefetch = false) => {
    if (!isRefetch || data === null) {
      setLoading(true);
    }
    setError(null);

    const controller = new AbortController();
    
    try {
      const result = await fetcherRef.current(controller.signal);
      setData(result);
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") {
        return;
      }
      const errMsg = err instanceof Error ? err.message : (err as any)?.message || "Unknown error";
      setError(err instanceof Error ? err : new Error(errMsg));
    } finally {
      setLoading(false);
    }
  }, [data]);

  useEffect(() => {
    const controller = new AbortController();
    let isSubscribed = true;

    fetcherRef.current(controller.signal)
      .then((result) => {
        if (isSubscribed) {
          setData(result);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isSubscribed && err.name !== "AbortError") {
          setError(err instanceof Error ? err : new Error(err?.message || "Unknown error"));
          setLoading(false);
        }
      });

    return () => {
      isSubscribed = false;
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, dependencies);

  return { data, error, loading, refetch: () => fetchData(true) };
}
