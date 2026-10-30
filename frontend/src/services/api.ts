const getHost = () => {
  if (typeof window === 'undefined') return '127.0.0.1';
  return window.location.hostname === 'localhost' ? '127.0.0.1' : window.location.hostname;
};

// Smart base URL resolver:
// 1. Runtime override via window.__CYVANTIS_API_URL__ or localStorage
// 2. Build-time Vite env variable (VITE_API_URL)
// 3. Render cloud automatic fallback: if frontend is on .onrender.com, use https://cyvantis.onrender.com
// 4. Local Vite proxy fallback: /api/v1
export const getApiBaseUrl = (): string => {
  if (typeof window !== 'undefined') {
    const custom = (window as any).__CYVANTIS_API_URL__ || localStorage.getItem('CYVANTIS_API_URL');
    if (custom) {
      const trimmed = String(custom).trim().replace(/\/+$/, '');
      return trimmed.endsWith('/api/v1') ? trimmed : `${trimmed}/api/v1`;
    }
  }

  const envApiUrl = import.meta.env.VITE_API_URL ? String(import.meta.env.VITE_API_URL).trim().replace(/\/+$/, '') : '';
  if (envApiUrl) {
    return envApiUrl.endsWith('/api/v1') ? envApiUrl : `${envApiUrl}/api/v1`;
  }

  // Automatic cloud detection for Render: if frontend is on *.onrender.com, route to https://cyvantis.onrender.com
  if (typeof window !== 'undefined' && window.location.hostname.endsWith('.onrender.com')) {
    return 'https://cyvantis.onrender.com/api/v1';
  }

  return typeof window !== 'undefined' ? '/api/v1' : `http://${getHost()}:8000/api/v1`;
};

export const API_BASE_URL = getApiBaseUrl();

export function getAuthToken(): string | null {
  return localStorage.getItem('cyvantis_token');
}

export function setAuthToken(token: string) {
  localStorage.setItem('cyvantis_token', token);
}

export function removeAuthToken() {
  localStorage.removeItem('cyvantis_token');
}

export async function apiRequest<T = any>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getAuthToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {})
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const response = await fetch(`${API_BASE_URL}${normalizedEndpoint}`, {
    ...options,
    headers
  });

  if (response.status === 401) {
    // Session expired or unauthenticated
    removeAuthToken();
    if (!window.location.pathname.includes('/login')) {
      window.location.href = '/login';
    }
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(errorData.detail || 'API Request failed');
  }

  // If response is file download or no content
  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

export function getWebSocketUrl(token?: string | null): string {
  let wsUrl: string;

  // 1. Explicit WebSocket URL override
  if (import.meta.env.VITE_WS_URL) {
    const customWs = String(import.meta.env.VITE_WS_URL).trim().replace(/\/+$/, '');
    wsUrl = customWs.endsWith('/ws/events') ? customWs : `${customWs}/api/v1/ws/events`;
  }
  // 2. Derive WebSocket URL from API_BASE_URL if configured
  else if (API_BASE_URL && API_BASE_URL.startsWith('http')) {
    const parsed = new URL(API_BASE_URL);
    const wsProto = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
    const basePath = parsed.pathname.replace(/\/+$/, '');
    wsUrl = `${wsProto}//${parsed.host}${basePath.endsWith('/api/v1') ? basePath : basePath + '/api/v1'}/ws/events`;
  }
  // 3. Fallback to current browser host
  else {
    const host = getHost();
    const isLocal = typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');
    const protocol = typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    
    // In local development without reverse proxy, backend is typically on port 8000
    // In production with reverse proxy, backend is on standard port 80/443
    const portPart = isLocal ? ':8000' : (window.location.port ? `:${window.location.port}` : '');
    wsUrl = `${protocol}//${host}${portPart}/api/v1/ws/events`;
  }

  const authToken = token || getAuthToken();
  return authToken ? `${wsUrl}?token=${encodeURIComponent(authToken)}` : wsUrl;
}

export async function downloadFile(endpoint: string, defaultFilename: string) {
  const token = getAuthToken();
  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const url = `${API_BASE_URL}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`;
  const response = await fetch(url, {
    method: 'GET',
    headers
  });

  if (response.status === 401) {
    removeAuthToken();
    if (!window.location.pathname.includes('/login')) {
      window.location.href = '/login';
    }
    throw new Error('Authentication required');
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(errorData.detail || 'Download failed');
  }

  let filename = defaultFilename;
  const disposition = response.headers.get('Content-Disposition');
  if (disposition && disposition.includes('filename=')) {
    const matches = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/.exec(disposition);
    if (matches && matches[1]) {
      filename = matches[1].replace(/['"]/g, '');
    }
  }

  const blob = await response.blob();
  const blobUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = blobUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(blobUrl);
}
