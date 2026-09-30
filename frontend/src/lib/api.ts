/**
 * WiFi Guard API Service
 * 
 * This service handles all communication between the React frontend
 * and the Flask backend. It provides type-safe methods for each endpoint.
 */

const API_BASE_URL = 'https://wifi-guard-production.up.railway.app';

export interface Device {
  ip: string;
  mac: string;
  hostname: string;
  vendor: string;
  device_type: string;
}

export interface ScanResponse {
  success: boolean;
  device_count: number;
  devices: Device[];
  error?: string;
}

export interface ApiResponse {
  message: string;
  status: string;
  module: string;
}

export async function scanNetwork(): Promise<ScanResponse> {
  const controller = new AbortController();

  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(`${API_BASE_URL}/scan`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Failed to scan network');
    }

    return await response.json();
  } catch (error) {
    clearTimeout(timeout);
    console.error('Error scanning network:', error);
    throw error;
  }
}

/**
 * Get API health status
 * 
 * @returns Promise<ApiResponse> - API status information
 */
export async function getApiStatus(): Promise<ApiResponse> {
  try {
    const response = await fetch(`${API_BASE_URL}/`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error('Failed to get API status');
    }

    const data: ApiResponse = await response.json();
    return data;
  } catch (error) {
    console.error('Error getting API status:', error);
    throw error;
  }
}

// Future endpoints to be added:
// - getNetworkHealth()
// - getThreats()
// - getDeviceDetails(ip: string)
