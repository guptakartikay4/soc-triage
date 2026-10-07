import { apiClient } from './client';
import type { TriageRunResponse } from '../types/api';

export const triageApi = {
  run: async (source: string = 'dataset', reset: boolean = true): Promise<TriageRunResponse> => {
    const { data } = await apiClient.post<TriageRunResponse>('/api/triage/run', { source, reset });
    return data;
  },
};
