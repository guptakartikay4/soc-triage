import { apiClient } from './client';
import type { IncidentSummaryResponse, IncidentDetailResponse, IncidentBriefResponse } from '../types/api';

export const incidentsApi = {
  list: async (params?: { priority?: string; limit?: number; offset?: number }): Promise<IncidentSummaryResponse[]> => {
    const { data } = await apiClient.get<IncidentSummaryResponse[]>('/api/incidents', { params });
    return data;
  },
  
  getDetail: async (incidentId: string): Promise<IncidentDetailResponse> => {
    const { data } = await apiClient.get<IncidentDetailResponse>(`/api/incidents/${incidentId}`);
    return data;
  },
  
  generateBrief: async (incidentId: string): Promise<IncidentBriefResponse> => {
    const { data } = await apiClient.post<IncidentBriefResponse>(`/api/incidents/${incidentId}/brief`);
    return data;
  },
  
  recordAction: async (incidentId: string, action: string, note?: string): Promise<{ status: string; action: string }> => {
    const payload = {
      action,
      note,
      timestamp: new Date().toISOString()
    };
    const { data } = await apiClient.post<{ status: string; action: string }>(`/api/incidents/${incidentId}/action`, payload);
    return data;
  },

  getDecisions: async (incidentId: string): Promise<any[]> => {
    const { data } = await apiClient.get<any[]>(`/api/analyst/incidents/${incidentId}/decisions`);
    return data;
  }
};
