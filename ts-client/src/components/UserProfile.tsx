'use client';

import { User } from 'oidc-client-ts';
import { useState } from 'react';

interface UserProfileProps {
  user: User;
}

export default function UserProfile({ user }: UserProfileProps) {
  const [showRawData, setShowRawData] = useState(false);
  const profile = user.profile;

  const formatDate = (timestamp?: number) => {
    if (!timestamp) return 'N/A';
    return new Date(timestamp * 1000).toLocaleString();
  };

  const getAvatarLetter = () => {
    const name = profile?.name || profile?.preferred_username || profile?.sub;
    return name ? name.charAt(0).toUpperCase() : 'U';
  };

  const displayFields = [
    { label: 'Name', value: profile?.name },
    { label: 'Username', value: profile?.preferred_username },
    { label: 'Email', value: profile?.email },
    { label: 'Email Verified', value: profile?.email_verified ? 'Yes' : 'No' },
    { label: 'Subject', value: profile?.sub },
    { label: 'Issued At', value: formatDate(profile?.iat) },
    { label: 'Expires', value: formatDate(profile?.exp) },
    { label: 'Audience', value: profile?.aud },
  ].filter(field => field.value !== undefined && field.value !== null);

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-2xl mx-auto">
        <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
          {/* Header Section */}
          <div className="bg-gradient-to-r from-blue-600 to-indigo-600 px-8 py-12 text-center">
            <div className="w-24 h-24 mx-auto bg-white bg-opacity-20 rounded-full flex items-center justify-center mb-4 backdrop-blur-sm">
              <span className="text-3xl font-bold text-white">
                {getAvatarLetter()}
              </span>
            </div>
            <h1 className="text-3xl font-bold text-white mb-2">
              Welcome Back!
            </h1>
            <p className="text-blue-100 text-lg">
              {profile?.name || profile?.preferred_username || 'User'}
            </p>
            <div className="mt-4">
              <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
                <svg className="w-4 h-4 mr-1" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                Authenticated
              </span>
            </div>
          </div>

          {/* Profile Information */}
          <div className="px-8 py-8">
            <h2 className="text-2xl font-semibold text-gray-900 mb-6">Profile Information</h2>
            
            <div className="grid gap-6">
              {displayFields.map((field, index) => (
                <div key={index} className="flex items-center justify-between py-3 border-b border-gray-100 last:border-b-0">
                  <span className="text-sm font-medium text-gray-500 uppercase tracking-wider">
                    {field.label}
                  </span>
                  <span className="text-gray-900 font-medium max-w-xs truncate text-right">
                    {String(field.value)}
                  </span>
                </div>
              ))}
            </div>

            {/* Token Information */}
            <div className="mt-8 p-4 bg-gray-50 rounded-lg">
              <h3 className="text-lg font-medium text-gray-900 mb-3">Token Details</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-500">Access Token</span>
                  <p className="text-gray-900 font-mono text-xs break-all">
                    {user.access_token.substring(0, 50)}...
                  </p>
                </div>
                <div>
                  <span className="text-gray-500">Token Type</span>
                  <p className="text-gray-900 font-medium">
                    {user.token_type || 'Bearer'}
                  </p>
                </div>
              </div>
            </div>

            {/* Raw Data Toggle */}
            <div className="mt-8 text-center">
              <button
                onClick={() => setShowRawData(!showRawData)}
                className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors"
              >
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
                {showRawData ? 'Hide' : 'Show'} Raw Data
              </button>
            </div>

            {/* Raw Data Display */}
            {showRawData && (
              <div className="mt-6 p-4 bg-gray-900 rounded-lg">
                <h4 className="text-sm font-medium text-gray-300 mb-3">Raw Profile Data</h4>
                <pre className="text-xs text-green-400 overflow-auto max-h-64 font-mono">
                  {JSON.stringify(profile, null, 2)}
                </pre>
              </div>
            )}

            {/* Actions */}
            <div className="mt-8 flex justify-center space-x-4">
              <a
                href="/"
                className="inline-flex items-center px-6 py-3 border border-transparent text-base font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors"
              >
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                </svg>
                Go to Dashboard
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}