import { expect } from 'chai';
import nano from 'nano';
import sinon from 'sinon';
import { CouchAuth } from '../lib/index';
import { getDBURL, timeoutPromise } from '../lib/util';
import { config as baseConfig } from './test.config';

describe('Session cache', function () {
  this.timeout(30000);

  const userDBName = 'sl_test-cache-users';
  const keysDBName = 'sl_test-cache-keys';
  const couch = nano(getDBURL(baseConfig.dbServer));
  const password = 'Password1!';
  const email = 'cached@example.com';

  const makeConfig = (sessionCacheTtl?: number) => ({
    ...baseConfig,
    dbServer: {
      ...baseConfig.dbServer,
      userDB: userDBName,
      couchAuthDB: keysDBName
    },
    local: {
      sendConfirmEmail: false,
      requireEmailConfirm: false,
      emailUsername: true,
      usernameLogin: false
    },
    security: {
      ...baseConfig.security,
      userHashing: { iterations: 1000 },
      sessionCacheTtl
    }
  });

  let uncached: CouchAuth;
  let cached: CouchAuth;
  let cachedToo: CouchAuth;
  let userId: string;

  const newSession = () =>
    uncached.createSession({ login: userId, provider: 'local', byUUID: true });
  const reads = (couchAuth: CouchAuth) =>
    sinon.spy((couchAuth as any).dbAuth, 'retrieveKey');

  before(async () => {
    await couch.db.create(userDBName);
    await couch.db.create(keysDBName);
    uncached = new CouchAuth(makeConfig() as any);
    cached = new CouchAuth(makeConfig(60) as any);
    cachedToo = new CouchAuth(makeConfig(60) as any);
    const userDB = couch.use(userDBName);
    for (let i = 0; i < 50; i++) {
      try {
        await userDB.get('_design/auth');
        break;
      } catch {
        await timeoutPromise(100);
      }
    }
    const signedUp = new Promise(resolve =>
      uncached.emitter.once('signup', resolve)
    );
    await uncached.createUser({ email, password, confirmPassword: password });
    await signedUp;
    userId = (await uncached.getUser(email))._id;
  });

  after(async () => {
    await couch.db.destroy(userDBName);
    await couch.db.destroy(keysDBName);
  });

  afterEach(() => sinon.restore());

  it('is off unless sessionCacheTtl is set', async () => {
    const s = await newSession();
    const spy = reads(uncached);
    await uncached.confirmSession(s.token, s.password);
    await uncached.confirmSession(s.token, s.password);
    expect(spy.callCount).to.equal(2);
  });

  it('reads _users only once while the entry is fresh', async () => {
    const s = await newSession();
    const spy = reads(cached);
    const first = await cached.confirmSession(s.token, s.password);
    const second = await cached.confirmSession(s.token, s.password);
    expect(spy.callCount).to.equal(1);
    expect(second).to.deep.equal(first);
    expect(second.roles).to.not.equal(first.roles); // a copy
  });

  it('still rejects a wrong password for a cached key', async () => {
    const s = await newSession();
    await cached.confirmSession(s.token, s.password);
    const err = await cached.confirmSession(s.token, 'wrong').catch(e => e);
    expect(err).to.deep.equal({ status: 401, message: 'invalid token' });
  });

  it('forgets a session on logout, also for other instances', async () => {
    const s = await newSession();
    await cached.confirmSession(s.token, s.password);
    await cachedToo.confirmSession(s.token, s.password);
    await uncached.logoutSession(s.token);
    for (const couchAuth of [cached, cachedToo]) {
      const err = await couchAuth
        .confirmSession(s.token, s.password)
        .catch(e => e);
      expect(err).to.deep.equal({ status: 401, message: 'invalid token' });
    }
  });

  it('never keeps an entry past the session expiry', async () => {
    const s = await newSession();
    // shorten the session to 300 ms in _users
    const keysDB = couch.use<any>(keysDBName);
    const keyDoc = await keysDB.get('org.couchdb.user:' + s.token);
    keyDoc.expires = Date.now() + 300;
    await keysDB.insert(keyDoc);
    await cached.confirmSession(s.token, s.password);
    await timeoutPromise(400);
    const err = await cached.confirmSession(s.token, s.password).catch(e => e);
    expect(err).to.deep.equal({ status: 401, message: 'invalid token' });
  });

  it('does not keep the session password', async () => {
    const s = await newSession();
    await cached.confirmSession(s.token, s.password);
    const entries = (cached as any).sessionCache.entries;
    expect(JSON.stringify([...entries.values()])).to.not.include(s.password);
  });
});
