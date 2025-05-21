import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import { securityConfig } from '../config/security';

class SecureApiClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: securityConfig.apiBaseUrl,
      headers: {
        'Content-Type': 'application/json',
        ...securityConfig.headers,
      },
      withCredentials: true, // Important for secure cookie handling
    });

    // Add request interceptor for additional security
    this.client.interceptors.request.use(
      (config) => {
        // Ensure all requests use HTTPS
        if (config.url?.startsWith('http://')) {
          config.url = config.url.replace('http://', 'https://');
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Add response interceptor for security checks
    this.client.interceptors.response.use(
      (response) => {
        // Verify security headers in response
        const securityHeaders = response.headers;
        if (!securityHeaders['strict-transport-security']) {
          console.warn('Missing HSTS header in response');
        }
        return response;
      },
      (error) => {
        if (error.response?.status === 401) {
          // Handle unauthorized access
          // You might want to redirect to login or refresh token
        }
        return Promise.reject(error);
      }
    );
  }

  // Secure GET request
  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return this.client.get(url, config);
  }

  // Secure POST request
  async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return this.client.post(url, data, config);
  }

  // Secure PUT request
  async put<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return this.client.put(url, data, config);
  }

  // Secure DELETE request
  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return this.client.delete(url, config);
  }
}

export const apiClient = new SecureApiClient(); 