'use client';

import { UserManager, UserManagerSettings, User } from 'oidc-client-ts';

// OIDC Configuration matching the Go example
const OIDC_ISSUER = 'http://localhost:49151';
const CLIENT_ID = '1234';
const CLIENT_SECRET = 'secret';
const REDIRECT_URL = 'http://localhost:49150/callback';

// Client authentication methods
export type ClientAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt';

// Configuration for different authentication methods
interface AuthMethodConfig {
  method: ClientAuthMethod;
  clientSecret?: string;
  privateKey?: string;
  keyId?: string;
}

// Default authentication method - can be changed as needed
let currentAuthMethod: ClientAuthMethod = 'client_secret_basic';
// let currentAuthMethod: ClientAuthMethod = 'client_secret_post';
// let currentAuthMethod: ClientAuthMethod = 'client_secret_jwt';

// Generate UserManager settings based on authentication method
function createUserManagerSettings(authMethod: ClientAuthMethod, config?: AuthMethodConfig): UserManagerSettings {
  const baseSettings: UserManagerSettings = {
    authority: OIDC_ISSUER,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URL,
    response_type: 'code',
    scope: 'openid',
    post_logout_redirect_uri: 'http://localhost:49150',
    includeIdTokenInSilentRenew: false,
    automaticSilentRenew: false,
    silent_redirect_uri: 'http://localhost:49150/callback',
    loadUserInfo: true,
  };

  switch (authMethod) {
    case 'client_secret_basic':
      return {
        ...baseSettings,
        client_secret: config?.clientSecret || CLIENT_SECRET,
        client_authentication: 'client_secret_basic',
      };

    case 'client_secret_post':
      return {
        ...baseSettings,
        client_secret: config?.clientSecret || CLIENT_SECRET,
        client_authentication: 'client_secret_post',
      };

    case 'client_secret_jwt':
      return {
        ...baseSettings,
        client_secret: config?.clientSecret || CLIENT_SECRET,
        client_authentication: 'client_secret_jwt',
        // For JWT authentication, you might need additional configuration
        // such as signing algorithm, key ID, etc.
        ...(config?.privateKey && { client_assertion_signing_alg: 'HS256' }),
        ...(config?.keyId && { client_assertion_signing_kid: config.keyId }),
      };

    default:
      throw new Error(`Unsupported authentication method: ${authMethod}`);
  }
}

let userManager: UserManager | null = null;
let currentAuthConfig: AuthMethodConfig | undefined = undefined;

export function getUserManager(): UserManager {
  if (typeof window === 'undefined') {
    throw new Error('UserManager can only be used in browser environment');
  }
  
  if (!userManager) {
    const settings = createUserManagerSettings(currentAuthMethod, currentAuthConfig);
    userManager = new UserManager(settings);
  }
  return userManager;
}

// Reset the UserManager when authentication method changes
function resetUserManager(): void {
  if (userManager) {
    userManager = null;
  }
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

// Authentication method configuration functions
export function setAuthenticationMethod(method: ClientAuthMethod, config?: AuthMethodConfig): void {
  currentAuthMethod = method;
  currentAuthConfig = config;
  resetUserManager();
}

export function getCurrentAuthenticationMethod(): ClientAuthMethod {
  return currentAuthMethod;
}

// Convenience functions for each authentication method
export function useClientSecretBasic(clientSecret?: string): void {
  setAuthenticationMethod('client_secret_basic', { 
    method: 'client_secret_basic',
    clientSecret 
  });
}

export function useClientSecretPost(clientSecret?: string): void {
  setAuthenticationMethod('client_secret_post', { 
    method: 'client_secret_post',
    clientSecret 
  });
}

export function useClientSecretJWT(clientSecret?: string, privateKey?: string, keyId?: string): void {
  setAuthenticationMethod('client_secret_jwt', { 
    method: 'client_secret_jwt',
    clientSecret,
    privateKey,
    keyId
  });
}
