'use client';

import { useEffect } from 'react';
import { startLogin } from '@/lib/oidc';

export default function LoginPage() {
  useEffect(() => {
    // Automatically start the login process when the page loads
    startLogin().catch(console.error);
  }, []);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Redirecting to login...
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Please wait while we redirect you to the authentication provider.
          </p>
        </div>
        <div className="flex justify-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-indigo-600"></div>
        </div>
      </div>
    </div>
  );
}