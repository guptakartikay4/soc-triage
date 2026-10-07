import { apiClient } from './client';
import type { DashboardMetricsResponse } from '../types/api';

export const metricsApi = {
  getOverview: async (): Promise<DashboardMetricsResponse> => {
    const { data } = await apiClient.get<DashboardMetricsResponse>('/api/metrics/overview');
    return data;
  },
};
