// Multi-user engine with Forced User mode per context.
// No external dependencies.

import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type UserRole = 'admin' | 'user' | 'guest' | 'api-key' | 'service' | string;

export interface UserCredentials {
  /** Username or email */
  username: string;
  /** Password (stored in-memory only — never persisted to disk here) */
  password?: string;
  /** Bearer token or API key */
  token?: string;
  /** Extra key-value pairs (e.g. MFA seed, client cert path) */
  extras?: Record<string, string>;
}

export interface User {
  id: string;
  name: string;
  role: UserRole;
  authMethodId: string;
  credentials: UserCredentials;
  /** Context IDs this user belongs to */
  contextIds: string[];
  /**
   * If true, all outgoing requests in the associated contexts will be sent
   * using this user's session — regardless of the operator's active session.
   */
  forcedUserMode: boolean;
  createdAt: string;
}

export interface CreateUserOptions {
  name: string;
  role?: UserRole;
  authMethodId: string;
  credentials: UserCredentials;
  contextIds?: string[];
  forcedUserMode?: boolean;
}

// ---------------------------------------------------------------------------
// In-process user store
// ---------------------------------------------------------------------------

const userStore = new Map<string, User>();

// contextId → forced user id
const forcedUserByContext = new Map<string, string>();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function createUser(options: CreateUserOptions): User {
  const user: User = {
    id: randomBytes(8).toString('hex'),
    name: options.name,
    role: options.role ?? 'user',
    authMethodId: options.authMethodId,
    credentials: options.credentials,
    contextIds: options.contextIds ?? [],
    forcedUserMode: options.forcedUserMode ?? false,
    createdAt: new Date().toISOString(),
  };
  userStore.set(user.id, user);
  return user;
}

export function getUser(id: string): User | undefined {
  return userStore.get(id);
}

export function deleteUser(id: string): boolean {
  // Clean up any forced-user bindings
  for (const [ctxId, uid] of forcedUserByContext.entries()) {
    if (uid === id) forcedUserByContext.delete(ctxId);
  }
  return userStore.delete(id);
}

/**
 * Returns all users that are associated with the given context id.
 */
export function getUsersForContext(contextId: string): User[] {
  return Array.from(userStore.values()).filter((u) => u.contextIds.includes(contextId));
}

/**
 * Sets a forced user for the given context.
 * Only one forced user is active per context at a time.
 *
 * @throws if the userId does not exist in the store
 */
export function setForcedUser(contextId: string, userId: string): void {
  if (!userStore.has(userId)) {
    throw new Error(`User "${userId}" does not exist`);
  }
  forcedUserByContext.set(contextId, userId);
}

/**
 * Clears the forced user for a context.
 */
export function clearForcedUser(contextId: string): void {
  forcedUserByContext.delete(contextId);
}

/**
 * Returns the forced user for a context, or undefined if none is set.
 */
export function getForcedUser(contextId: string): User | undefined {
  const uid = forcedUserByContext.get(contextId);
  return uid ? userStore.get(uid) : undefined;
}

/**
 * Returns true if a forced user is currently active for the given context.
 */
export function isForcedUserMode(contextId: string): boolean {
  return forcedUserByContext.has(contextId);
}

/**
 * Adds a user to a context (by id). Idempotent.
 */
export function addUserToContext(userId: string, contextId: string): void {
  const user = userStore.get(userId);
  if (!user) throw new Error(`User "${userId}" does not exist`);
  if (!user.contextIds.includes(contextId)) {
    user.contextIds.push(contextId);
  }
}

/**
 * Removes a user from a context. Clears forced-user binding if applicable.
 */
export function removeUserFromContext(userId: string, contextId: string): void {
  const user = userStore.get(userId);
  if (!user) return;
  user.contextIds = user.contextIds.filter((id) => id !== contextId);
  const forced = forcedUserByContext.get(contextId);
  if (forced === userId) forcedUserByContext.delete(contextId);
}

export function listUsers(): User[] {
  return Array.from(userStore.values());
}
