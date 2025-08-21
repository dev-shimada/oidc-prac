'use client';

import { useEffect, useState } from 'react';
import { handleCallback } from '@/lib/oidc';
import { User } from 'oidc-client-ts';

export default function CallbackPage() {
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const processCallback = async () => {
      try {
        const userData = await handleCallback();
        setUser(userData);
        
        // Redirect to home page after successful login
        setTimeout(() => {
          window.location.href = '/';
        }, 2000);
      } catch (err) {
        console.error('Callback error:', err);
        setError(err instanceof Error ? err.message : 'Authentication failed');
      } finally {
        setLoading(false);
      }
    };

    processCallback();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full space-y-8">
          <div>
            <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
              Processing login...
            </h2>
            <p className="mt-2 text-center text-sm text-gray-600">
              Please wait while we complete your authentication.
            </p>
          </div>
          <div className="flex justify-center">
            <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-indigo-600"></div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full space-y-8">
          <div>
            <h2 className="mt-6 text-center text-3xl font-extrabold text-red-600">
              Authentication Failed
            </h2>
            <p className="mt-2 text-center text-sm text-gray-600">
              {error}
            </p>
            <div className="mt-4 text-center">
              <a 
                href="/login" 
                className="text-indigo-600 hover:text-indigo-500 font-medium"
              >
                Try again
              </a>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-green-600">
            Login Successful!
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Welcome, {user?.profile?.name || user?.profile?.sub}
          </p>
          <div className="mt-4 p-4 bg-gray-100 rounded-md">
            <pre className="text-xs overflow-auto">
              {JSON.stringify(user?.profile, null, 2)}
            </pre>
          </div>
          <p className="mt-4 text-center text-sm text-gray-500">
            Redirecting to home page...
          </p>
        </div>
      </div>
    </div>
  );
}