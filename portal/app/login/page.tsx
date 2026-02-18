import { Card } from '@/components/ui/card';

type LoginPageProps = {
  searchParams?: {
    redirect?: string;
    error?: string;
  };
};

function renderError(code?: string): string | null {
  if (!code) return null;
  if (code === 'username_password_tenant_required') return 'Username, password, and tenant ID are required.';
  if (code === 'invalid_credentials_or_tenant') return 'Invalid credentials or tenant ID.';
  return 'Authentication failed.';
}

export default function LoginPage({ searchParams }: LoginPageProps) {
  const redirect = searchParams?.redirect ?? '/portal/findings';
  const error = renderError(searchParams?.error);

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <Card>
        <h1 className="mb-2 text-xl font-semibold">Client Login</h1>
        <p className="mb-4 text-sm text-muted">Sign in with your assigned portal credentials and tenant ID.</p>
        {error ? <p className="mb-4 text-sm text-red-400">{error}</p> : null}
        <form action="/api/auth/login" method="post" className="space-y-3">
          <input type="hidden" name="redirect" value={redirect} />
          <label className="block text-sm">
            <span className="mb-1 block text-muted">Username</span>
            <input
              type="text"
              name="username"
              required
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-muted">Password</span>
            <input
              type="password"
              name="password"
              required
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-muted">Tenant ID (UUID)</span>
            <input
              type="text"
              name="tenant_id"
              defaultValue="00000000-0000-0000-0000-000000000001"
              required
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            />
          </label>
          <button
            type="submit"
            className="w-full rounded bg-accent px-4 py-2 font-medium text-slate-950 hover:opacity-90"
          >
            Login
          </button>
        </form>
      </Card>
    </main>
  );
}
