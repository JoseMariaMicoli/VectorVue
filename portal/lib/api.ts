import { cookies } from 'next/headers';

import { API_URL } from '@/lib/config';

const TOKEN_COOKIE = 'vv_access_token';

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const token = cookies().get(TOKEN_COOKIE)?.value;
  const headers = new Headers(init?.headers);

  if (!headers.has('Content-Type') && init?.body) {
    headers.set('Content-Type', 'application/json');
  }

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    credentials: 'include',
    cache: 'no-store',
    headers
  });

  if (!res.ok) {
    const message = await res.text();
    throw new Error(`API ${res.status}: ${message}`);
  }

  return (await res.json()) as T;
}
