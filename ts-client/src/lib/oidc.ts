'use client';

import { UserManager, UserManagerSettings, User } from 'oidc-client-ts';

// OIDC Configuration matching the Go example
const OIDC_ISSUER = 'http://localhost:49151';
const CLIENT_ID = '1234';
const REDIRECT_URL = 'http://localhost:49150/callback';

// UserManager configuration for client-side
const userManagerSettings: UserManagerSettings = {
  authority: OIDC_ISSUER,
  client_id: CLIENT_ID,
  client_secret: 'secret',
  redirect_uri: REDIRECT_URL,
  response_type: 'code',
  scope: 'openid',
  post_logout_redirect_uri: 'http://localhost:49150',
  includeIdTokenInSilentRenew: false,
  automaticSilentRenew: false,
  silent_redirect_uri: 'http://localhost:49150/callback',
  // Use client_secret_basic authentication
  client_authentication: 'client_secret_basic',
  loadUserInfo: true,
};

let userManager: UserManager | null = null;

export function getUserManager(): UserManager {
  if (typeof window === 'undefined') {
    throw new Error('UserManager can only be used in browser environment');
  }
  
  if (!userManager) {
    userManager = new UserManager(userManagerSettings);
  }
  return userManager;
}

export async function startLogin(): Promise<void> {
  const manager = getUserManager();
  await manager.signinRedirect();
}

export async function handleCallback(): Promise<User> {
  const manager = getUserManager();
  
  // Process the callback and get the user
  const user = await manager.signinCallback();
  
  if (!user) {
    throw new Error('No user returned from callback');
  }
  
  return user;
}

export async function getUser(): Promise<User | null> {
  const manager = getUserManager();
  return await manager.getUser();
}

export async function signout(): Promise<void> {
  const manager = getUserManager();
  await manager.signoutRedirect();
}

export async function removeUser(): Promise<void> {
  const manager = getUserManager();
  await manager.removeUser();
}
