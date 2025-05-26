import axios, { AxiosInstance, AxiosRequestConfig, AxiosError } from 'axios';
import { securityConfig } from '../config/security';

// Define the response data type
interface ApiResponse<T = any> {
  status: string;
  detail?: string;
  data?: T;
}

class SecureApiClient {
  private client: AxiosInstance;

  constructor() {
    // In development, use a proxy to handle SSL certificate issues
    const baseURL = process.env.NODE_ENV === 'development' 
      ? '/api' // This will be proxied by the development server
      : securityConfig.apiBaseUrl;

    this.client = axios.create({
      baseURL,
      headers: {
        'Content-Type': 'application/json',
        ...securityConfig.headers,
      },
      withCredentials: true,
      timeout: 10000,
    });

    // Add request interceptor for additional security
    this.client.interceptors.request.use(
      (config) => {
        // In development, we don't need to modify the URL since we're using a proxy
        if (process.env.NODE_ENV !== 'development' && config.url?.startsWith('http://')) {
          config.url = config.url.replace('http://', 'https://');
        }
        return config;
      },
      (error) => {
        console.error('Request error:', error);
        return Promise.reject(error);
      }
    );

    // Add response interceptor for security checks and error handling
    this.client.interceptors.response.use(
      (response) => {
        // Verify security headers in response
        const securityHeaders = response.headers;
        if (!securityHeaders['strict-transport-security']) {
          console.warn('Missing HSTS header in response');
        }
        return response;
      },
      (error: AxiosError<ApiResponse>) => {
        console.error('Response error:', error);
        
        // Handle network errors
        if (error.code === 'ERR_NETWORK') {
          return Promise.reject(new Error('Unable to connect to the server. Please check your internet connection and try again.'));
        }
        
        // Handle SSL certificate errors
        if (error.code === 'ERR_CERT_AUTHORITY_INVALID') {
          if (process.env.NODE_ENV === 'development') {
            console.warn('SSL Certificate Error in development mode. Using proxy to handle this.');
            // Retry the request with the proxy
            const originalConfig = error.config;
            if (originalConfig) {
              originalConfig.baseURL = '/api';
              return this.client(originalConfig);
            }
          }
          return Promise.reject(new Error('Unable to establish a secure connection to the server. Please ensure you\'re using a trusted network.'));
        }

        // Handle unauthorized access
        if (error.response?.status === 401) {
          return Promise.reject(new Error('Your session has expired. Please log in again.'));
        }

        // Handle other error responses
        if (error.response?.data?.detail) {
          return Promise.reject(new Error(error.response.data.detail));
        }

        // Handle timeout
        if (error.code === 'ECONNABORTED') {
          return Promise.reject(new Error('Request timed out. Please try again.'));
        }

        // Default error message
        return Promise.reject(new Error('An unexpected error occurred. Please try again.'));
      }
    );
  }

  // Secure GET request
  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await this.client.get<ApiResponse<T>>(url, config);
      return response.data.data as T;
    } catch (error) {
      console.error('GET request failed:', error);
      throw error;
    }
  }

  // Secure POST request
  async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await this.client.post<T>(url, data, config);
      // Return the response data directly without expecting a nested data field
      return response.data;
    } catch (error) {
      console.error('POST request failed:', error);
      throw error;
    }
  }

  // Secure PUT request
  async put<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await this.client.put<ApiResponse<T>>(url, data, config);
      return response.data.data as T;
    } catch (error) {
      console.error('PUT request failed:', error);
      throw error;
    }
  }

  // Secure DELETE request
  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await this.client.delete<ApiResponse<T>>(url, config);
      return response.data.data as T;
    } catch (error) {
      console.error('DELETE request failed:', error);
      throw error;
    }
  }
}

export const apiClient = new SecureApiClient(); 