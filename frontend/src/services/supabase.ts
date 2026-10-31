// CYVANTIS Supabase Integration Client Helper
// Provides zero-dependency REST queries directly to Supabase PostgREST API when configured,
// or seamless fallback to CYVANTIS backend endpoints.

const SUPABASE_URL = (import.meta.env.VITE_SUPABASE_URL || '').replace(/\/+$/, '');
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured = (): boolean => {
  return Boolean(SUPABASE_URL && SUPABASE_ANON_KEY);
};

export async function supabaseRestQuery<T = any>(
  table: string,
  params: Record<string, string> = {}
): Promise<T[]> {
  if (!isSupabaseConfigured()) {
    throw new Error('Supabase URL or Anon Key is not configured in client environment.');
  }

  const queryString = new URLSearchParams(params).toString();
  const url = `${SUPABASE_URL}/rest/v1/${table}${queryString ? `?${queryString}` : ''}`;

  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ message: response.statusText }));
    throw new Error(err.message || 'Supabase query failed');
  }

  return response.json();
}

