'use client';

import { useEffect, useState } from 'react';
import { getUser, signout } from '@/lib/oidc';
import { User } from 'oidc-client-ts';

export default function AuthStatus() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkUser = async () => {
      try {
        const userData = await getUser();
        setUser(userData);
      } catch (error) {
        console.error('Error checking user:', error);
      } finally {
        setLoading(false);
      }
    };

    checkUser();
  }, []);

  const handleSignout = async () => {
    try {
      await signout();
    } catch (error) {
      console.error('Signout error:', error);
    }
  };

  if (loading) {
    return (
      <div className="mb-8 p-4 bg-gray-100 rounded-lg">
        <p className="text-sm text-gray-600">Checking authentication status...</p>
      </div>
    );
  }

  if (user) {
    return (
      <div className="mb-8 p-4 bg-green-100 rounded-lg">
        <h3 className="text-lg font-semibold text-green-800 mb-2">
          Welcome, {user.profile?.name || user.profile?.sub}!
        </h3>
        <p className="text-sm text-green-700 mb-4">
          You are successfully authenticated.
        </p>
        <div className="flex gap-4">
          <button
            onClick={handleSignout}
            className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors"
          >
            Sign Out
          </button>
        </div>
        <details className="mt-4">
          <summary className="cursor-pointer text-sm text-green-700 hover:text-green-800">
            View Profile Details
          </summary>
          <pre className="mt-2 p-2 bg-white rounded text-xs overflow-auto">
            {JSON.stringify(user.profile, null, 2)}
          </pre>
        </details>
      </div>
    );
  }

  return (
    <div className="mb-8 p-4 bg-blue-100 rounded-lg">
      <h3 className="text-lg font-semibold text-blue-800 mb-2">
        Not Authenticated
      </h3>
      <p className="text-sm text-blue-700 mb-4">
        Please sign in to access protected resources.
      </p>
      <a
        href="/login"
        className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors inline-block"
      >
        Sign In
      </a>
    </div>
  );
}