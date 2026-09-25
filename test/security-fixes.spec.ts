import { expect } from 'chai';
import express from 'express';
import { existsSync } from 'fs';
import http from 'http';
import nano from 'nano';
import request from 'superagent';
import { CouchAuth } from '../lib/index';
import { CouchAdapter } from '../lib/dbauth/couchdb';
import { OAuth } from '../lib/oauth';
import {
  getDBURL,
  getSecurityDoc,
  putSecurityDoc,
  timeoutPromise
} from '../lib/util';
import { config as baseConfig } from './test.config';

describe('Security fixes', function () {
  this.timeout(30000);

  const port = 5002;
  const portNoPw = 5003;
  const server = `http://localhost:${port}`;
  const serverNoPw = `http://localhost:${portNoPw}`;
  const userDBName = 'sl_test-secfix-users';
  const keysDBName = 'sl_test-secfix-keys';
  const couch = nano(getDBURL(baseConfig.dbServer));
  const password = 'Password1!';
  const alice = 'alice@example.com';
  const bob = 'bob@example.com';
  const carol = 'carol@example.com';
  const dave = 'dave@example.com';
  let couchAuth: CouchAuth;
  const httpServers: http.Server[] = [];

  const config = {
    ...baseConfig,
    dbServer: {
      ...baseConfig.dbServer,
      userDB: userDBName,
      couchAuthDB: keysDBName
    },
    local: {
      sendConfirmEmail: true,
      requireEmailConfirm: true,
      emailUsername: true,
      usernameLogin: false
    },
    security: {
      ...baseConfig.security,
      loginRateLimit: { delayAfter: 100 },
      maxFailedLogins: 3,
      lockoutTime: 600,
      userHashing: { iterations: 1000 }
    }
  };

  const post = (url: string, body: object, session?: any, pw?: string) => {
    const req = request.post(url).send(body);
    if (session) {
      req.set(
        'Authorization',
        `Bearer ${session.token}:${pw ?? session.password}`
      );
    }
    return req.then(
      res => res,
      err => err.response
    );
  };
  const login = async (username: string) =>
    (await post(`${server}/auth/login`, { username, password })).body;
  const sessionStatus = (session: any) =>
    request
      .get(`${server}/auth/session`)
      .set('Authorization', `Bearer ${session.token}:${session.password}`)
      .then(
        res => res.status,
        err => err.status
      );

  const listen = (instance: CouchAuth, p: number) => {
    const app = express();
    app.use(express.json());
    app.use('/auth', instance.router);
    httpServers.push(app.listen(p));
  };

  const signUp = async (email: string) => {
    const signedUp = new Promise(resolve =>
      couchAuth.emitter.once('signup', resolve)
    );
    const emailToken = new Promise<string>(resolve =>
      couchAuth.emitter.once('confirm-email-token', ({ token }) =>
        resolve(token)
      )
    );
    await couchAuth.createUser({ email, password, confirmPassword: password });
    await signedUp;
    await couchAuth.verifyEmail(await emailToken);
  };

  before(async () => {
    await couch.db.create(userDBName);
    await couch.db.create(keysDBName);
    couchAuth = new CouchAuth(config as any);
    const userDB = couch.use(userDBName);
    for (let i = 0; i < 50; i++) {
      try {
        await userDB.get('_design/auth');
        break;
      } catch {
        await timeoutPromise(100);
      }
    }
    listen(couchAuth, port);
    listen(
      new CouchAuth({
        ...config,
        local: { ...config.local, requirePasswordOnEmailChange: false }
      } as any),
      portNoPw
    );
    await signUp(alice);
    await signUp(bob);
    await signUp(carol);
    await signUp(dave);
  });

  after(async () => {
    httpServers.forEach(s => s.close());
    await couch.db.destroy(userDBName);
    await couch.db.destroy(keysDBName);
  });

  it('needs the session password to log out', async () => {
    const session = await login(alice);
    for (const route of ['logout', 'logout-all']) {
      const res = await post(`${server}/auth/${route}`, {}, session, 'wrong');
      expect(res.status).to.equal(401);
    }
    expect(await sessionStatus(session)).to.equal(200);
    const res = await post(`${server}/auth/logout`, {}, session);
    expect(res.status).to.equal(200);
    expect(await sessionStatus(session)).to.equal(401);
  });

  it("doesn't delete another user with their password", async () => {
    const session = await login(alice);
    const res = await post(
      `${server}/auth/request-deletion`,
      { username: bob, password },
      session
    );
    expect(res.status).to.equal(401);
    await timeoutPromise(200);
    expect(await couchAuth.getUser(bob)).to.be.an('object');
    expect(await couchAuth.getUser(alice)).to.be.an('object');
  });

  it("doesn't change another user's email with their password", async () => {
    const session = await login(alice);
    const res = await post(
      `${server}/auth/change-email`,
      { username: bob, password, newEmail: 'stolen@example.com' },
      session
    );
    expect(res.status).to.equal(401);
    await timeoutPromise(200);
    expect((await couchAuth.getUser(bob)).unverifiedEmail).to.equal(undefined);
  });

  it("changes the session user's email with the password", async () => {
    const session = await login(alice);
    const res = await post(
      `${server}/auth/change-email`,
      { username: alice, password, newEmail: 'alice2@example.com' },
      session
    );
    expect(res.status).to.equal(200);
    await timeoutPromise(200);
    const doc = await couchAuth.getUser(alice);
    expect(doc.unverifiedEmail.email).to.equal('alice2@example.com');
  });

  it('changes the email without password if not required', async () => {
    const session = await login(bob);
    const missing = await post(`${serverNoPw}/auth/change-email`, {}, session);
    expect(missing.status).to.equal(400);
    const res = await post(
      `${serverNoPw}/auth/change-email`,
      { newEmail: 'bob2@example.com' },
      session
    );
    expect(res.status).to.equal(200);
    await timeoutPromise(200);
    const doc = await couchAuth.getUser(bob);
    expect(doc.unverifiedEmail.email).to.equal('bob2@example.com');
  });

  it('rejects a reset for an unknown username with 400', async () => {
    const token = new Promise<string>(resolve =>
      couchAuth.emitter.once('forgot-password', ({ token }) => resolve(token))
    );
    await couchAuth.forgotPassword(alice, {});
    const err = await couchAuth
      .resetPassword({
        token: await token,
        username: 'nobody@example.com',
        password: 'NewPassword1!',
        confirmPassword: 'NewPassword1!'
      })
      .catch(e => e);
    expect(err.status).to.equal(400);
  });

  it('changes the password of the session user', async () => {
    const session = await login(bob);
    const res = await post(
      `${server}/auth/password-change`,
      {
        currentPassword: password,
        newPassword: 'Password2!',
        confirmPassword: 'Password2!'
      },
      session
    );
    expect(res.status).to.equal(200);
    const doc = await couchAuth.getUser(bob);
    await couchAuth.changePassword(doc._id, password);
  });

  it('deletes the session user with the password', async () => {
    const session = await login(alice);
    const deleted = new Promise(resolve =>
      couchAuth.emitter.once('user-deleted', resolve)
    );
    const res = await post(
      `${server}/auth/request-deletion`,
      { username: alice, password },
      session
    );
    expect(res.status).to.equal(200);
    await deleted;
    expect(await couchAuth.getUser(alice)).to.equal(null);
    expect(await couchAuth.getUser(bob)).to.be.an('object');
  });

  it('counts concurrent failed logins, and a reset lifts the lock', async () => {
    const attempts = [];
    for (let i = 0; i < 5; i++) {
      attempts.push(
        post(`${server}/auth/login`, { username: carol, password: 'Wrong1!!' })
      );
    }
    await Promise.all(attempts);
    const local = (await couchAuth.getUser(carol)).local;
    expect(local.failedLoginAttempts).to.equal(5);
    expect(local.lockedUntil).to.be.greaterThan(Date.now());

    const token = new Promise<string>(resolve =>
      couchAuth.emitter.once('forgot-password', ({ token }) => resolve(token))
    );
    await couchAuth.forgotPassword(carol, {});
    const newPassword = 'Password2!';
    await couchAuth.resetPassword({
      token: await token,
      username: carol,
      password: newPassword,
      confirmPassword: newPassword
    });
    const doc = await couchAuth.getUser(carol);
    expect(doc.local.lockedUntil).to.equal(undefined);
    expect(doc.local.failedLoginAttempts).to.equal(undefined);
    const res = await post(`${server}/auth/login`, {
      username: carol,
      password: newPassword
    });
    expect(res.status).to.equal(200);
  });

  it('counts wrong current passwords on password change', async () => {
    const session = await login(dave);
    const change = (currentPassword: string) =>
      post(
        `${server}/auth/password-change`,
        {
          currentPassword,
          newPassword: 'Password2!',
          confirmPassword: 'Password2!'
        },
        session
      );
    for (let i = 0; i < 3; i++) {
      expect((await change('Wrong1!!')).status).to.equal(400);
    }
    expect((await couchAuth.getUser(dave)).local.failedLoginAttempts).to.equal(
      3
    );
    // locked: the right password gets the same answer as a wrong one
    const right = await change(password);
    const wrong = await change('Wrong1!!');
    expect(right.status).to.equal(403);
    expect(right.body).to.deep.equal(wrong.body);
  });

  it('slows down password reset guesses from one IP by default', async () => {
    const reset = (i: number) =>
      post(`${server}/auth/password-reset`, {
        token: 'guess' + i,
        username: `nobody${i}@example.com`,
        password: 'Password2!',
        confirmPassword: 'Password2!'
      });
    for (let i = 0; i < 3; i++) {
      expect((await reset(i)).status).to.equal(400);
    }
    const start = Date.now();
    await reset(3);
    expect(Date.now() - start).to.be.greaterThan(400);
  });

  it('keeps the admin roles when the members have none', async () => {
    const dbName = 'sl_test-secfix-security';
    await couch.db.create(dbName);
    try {
      const db = couch.use(dbName);
      await putSecurityDoc(couch, db, {
        admins: { names: [], roles: ['boss'] },
        members: { names: [] }
      });
      const adapter = new CouchAdapter(undefined, couch, config as any);
      await adapter.initSecurity(db, ['admin2'], ['member']);
      const secDoc = await getSecurityDoc(couch, db);
      expect(secDoc.admins.roles).to.deep.equal(['boss', 'admin2']);
      expect(secDoc.members.roles).to.deep.equal(['member']);
    } finally {
      await couch.db.destroy(dbName);
    }
  });

  describe('OAuth callback', () => {
    const provider = 'facebook';
    const fakePassport = {
      authenticate: () => (_req, _res, next) => next()
    } as any;
    const newOAuth = (security: object, providerConfig: object = {}) =>
      new OAuth(express.Router(), fakePassport, undefined, {
        security,
        providers: {
          [provider]: { credentials: { clientID: 'x' }, ...providerConfig }
        }
      } as any);

    it('needs a target origin for the default template', () => {
      expect(() => newOAuth({}).registerProvider(provider, () => {})).to.throw(
        /oauthTargetOrigin/
      );
      expect(() =>
        newOAuth({}, { template: 'custom.njk' }).registerProvider(
          provider,
          () => {}
        )
      ).not.to.throw();
    });

    it('posts the session only to the target origin, script-safe', () => {
      const oauth = newOAuth({ oauthTargetOrigin: 'https://app.example.com' });
      expect(existsSync(oauth['getTemplate'](provider))).to.equal(true);
      const html: string = oauth['renderCallback'](provider, {
        error: null,
        session: { name: '</script><script>alert(1)</script>' },
        link: null
      });
      expect(html).to.include('var targetOrigin = "https://app.example.com";');
      expect(html).not.to.include("'*'");
      expect(html).not.to.include('</script><script>');
      expect(html).to.include('\\u003c/script\\u003e');
      expect(html).not.to.include('&quot;');
    });
  });
});
