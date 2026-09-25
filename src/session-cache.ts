import { Config } from './types/config';
import { hashesEqual, hashToken } from './util';

export interface ConfirmedSession {
  key: string;
  _id: string;
  user_uid: string;
  expires: number;
  roles: string[];
  provider: string;
}

interface Entry {
  passwordHash: string;
  session: ConfirmedSession;
  until: number;
}

/** one cache per `_users` db, shared by the CouchAuth instances of a process */
const caches = new Map<string, SessionCache>();

function cacheId(config: Partial<Config>) {
  const db = config.dbServer;
  return `${db.protocol}${db.host}/${db.couchAuthDB}`;
}

/**
 * Short-lived in-memory cache of verified sessions (`security.sessionCacheTtl`),
 * so that each authenticated request doesn't read `_users`. It keeps only a
 * hash of the session password. Keys removed by this process are evicted at
 * once; other processes see a logout only when their entry expires.
 */
export class SessionCache {
  private entries = new Map<string, Entry>();

  private constructor(private ttlMs: number) {}

  /** `undefined` if the cache is off */
  static for(config: Partial<Config>): SessionCache | undefined {
    const ttl = config.security?.sessionCacheTtl;
    if (!ttl) {
      return undefined;
    }
    const id = cacheId(config);
    if (!caches.has(id)) {
      caches.set(id, new SessionCache(ttl * 1000));
    }
    return caches.get(id);
  }

  /**
   * Drops removed or replaced keys from the cache of this `_users` db, also
   * when the calling instance doesn't use the cache itself.
   */
  static evict(config: Partial<Config>, keys: string | string[]) {
    caches.get(cacheId(config))?.delete(keys);
  }

  get(key: string, password: string): ConfirmedSession | undefined {
    const entry = this.entries.get(key);
    if (!entry) {
      return undefined;
    }
    if (entry.until <= Date.now()) {
      this.entries.delete(key);
      return undefined;
    }
    if (!hashesEqual(hashToken(password), entry.passwordHash)) {
      return undefined;
    }
    return { ...entry.session, roles: [...entry.session.roles] };
  }

  set(key: string, password: string, session: ConfirmedSession) {
    const now = Date.now();
    if (this.entries.size >= 10000) {
      for (const [k, e] of this.entries) {
        if (e.until <= now) {
          this.entries.delete(k);
        }
      }
    }
    this.entries.set(key, {
      passwordHash: hashToken(password),
      session: { ...session, roles: [...session.roles] },
      until: Math.min(now + this.ttlMs, session.expires)
    });
  }

  delete(keys: string | string[]) {
    for (const key of Array.isArray(keys) ? keys : [keys]) {
      this.entries.delete(key);
    }
  }
}
