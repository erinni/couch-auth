import { expect } from 'chai';
import express from 'express';
import http from 'http';
import nano from 'nano';
import request from 'superagent';
import { CouchAuth } from '../lib/index';
import { UserHashing } from '../lib/user-hashing';
import { getDBURL, hashesEqual, timeoutPromise } from '../lib/util';
import { config as baseConfig } from './test.config';

describe('Login hardening', function () {
  this.timeout(30000);

  const port = 5001;
  const server = `http://localhost:${port}`;
  const userDBName = 'sl_test-hardening-users';
  const keysDBName = 'sl_test-hardening-keys';
  const couch = nano(getDBURL(baseConfig.dbServer));
  const password = 'Password1!';
  const email = 'locked@example.com';
  let couchAuth: CouchAuth;
  let httpServer: http.Server;

  const config = {
    ...baseConfig,
    dbServer: {
      ...baseConfig.dbServer,
      userDB: userDBName,
      couchAuthDB: keysDBName
    },
    // same login setup as the backend: email as username, no consents
    local: {
      sendConfirmEmail: true,
      requireEmailConfirm: true,
      emailUsername: true,
      usernameLogin: false
    },
    security: {
      ...baseConfig.security,
      maxFailedLogins: 3,
      lockoutTime: 1,
      // keep the per-username slow down out of the way of the lockout tests
      loginRateLimit: { delayAfter: 100 },
      loginRateLimitPerIp: { delayAfter: 25, delayMs: 300 },
      userHashing: { iterations: 1000 }
    }
  };

  const login = (username: string, pw: string) =>
    request
      .post(`${server}/auth/login`)
      .send({ username, password: pw })
      .then(
        res => res,
        err => err.response
      );

  const getLocal = async () => {
    const user = await couchAuth.getUser(email);
    return user.local;
  };

  before(async () => {
    await couch.db.create(userDBName);
    await couch.db.create(keysDBName);
    couchAuth = new CouchAuth(config as any);
    // the design doc is seeded without being awaited by the constructor
    const userDB = couch.use(userDBName);
    for (let i = 0; i < 50; i++) {
      try {
        await userDB.get('_design/auth');
        break;
      } catch {
        await timeoutPromise(100);
      }
    }
    const app = express();
    app.use(express.json());
    app.use('/auth', couchAuth.router);
    httpServer = app.listen(port);

    const signedUp = new Promise(resolve =>
      couchAuth.emitter.once('signup', resolve)
    );
    const emailToken = new Promise<string>(resolve =>
      couchAuth.emitter.once('confirm-email-token', ({ token }) =>
        resolve(token)
      )
    );
    await couchAuth.createUser({
      email,
      password,
      confirmPassword: password
    });
    await signedUp;
    await couchAuth.verifyEmail(await emailToken);
  });

  after(async () => {
    httpServer.close();
    await couch.db.destroy(userDBName);
    await couch.db.destroy(keysDBName);
  });

  it('compares hashes only when they are equal', () => {
    expect(hashesEqual('abcd', 'abcd')).to.equal(true);
    expect(hashesEqual('abcd', 'abce')).to.equal(false);
    expect(hashesEqual('abcd', 'abcdef')).to.equal(false);
    expect(hashesEqual(undefined, 'abcd')).to.equal(false);
  });

  it('takes as long for a missing hash as for a real one', async () => {
    const hashing = new UserHashing({
      security: { userHashing: { iterations: 200000 } }
    } as any);
    const real = await hashing.hashUserPassword('secret');
    const time = async (hashObj: any) => {
      const start = process.hrtime.bigint();
      const result = await hashing.verifyUserPassword(hashObj, 'wrong').then(
        () => true,
        err => err
      );
      expect(result).to.equal(false);
      return Number(process.hrtime.bigint() - start);
    };
    await time({}); // creates the dummy hash
    const missing = await time({});
    const existing = await time(real);
    expect(missing).to.be.greaterThan(existing / 2);
  });

  it('answers the same for an unknown user and a wrong password', async () => {
    const unknown = await login('nobody@example.com', password);
    const wrong = await login(email, 'Wrong1!!');
    expect(unknown.status).to.equal(401);
    expect(wrong.status).to.equal(401);
    expect(wrong.body).to.deep.equal(unknown.body);
    await timeoutPromise(1100);
  });

  it('locks the account after maxFailedLogins', async () => {
    for (let i = 0; i < 3; i++) {
      expect((await login(email, 'Wrong1!!')).status).to.equal(401);
    }
    const local = await getLocal();
    expect(local.failedLoginAttempts).to.equal(3);
    expect(local.lockedUntil).to.be.greaterThan(Date.now());
  });

  it('tells about the lock only who knows the password', async () => {
    const wrong = await login(email, 'Wrong1!!');
    expect(wrong.status).to.equal(401);
    expect(wrong.body.message).to.equal('Invalid username or password');
    const right = await login(email, password);
    expect(right.status).to.equal(401);
    expect(right.body.lockedUntil).to.be.a('number');
    // failures during the lock don't extend it
    expect((await getLocal()).failedLoginAttempts).to.equal(3);
  });

  it('lets the user in once the lock expires, and clears it', async () => {
    await timeoutPromise(1100);
    const res = await login(email, password);
    expect(res.status).to.equal(200);
    const local = await getLocal();
    expect(local.failedLoginAttempts).to.equal(undefined);
    expect(local.lastFailedLogin).to.equal(undefined);
    expect(local.lockedUntil).to.equal(undefined);
  });

  it('forgets failures older than lockoutTime', async () => {
    await login(email, 'Wrong1!!');
    await login(email, 'Wrong1!!');
    await timeoutPromise(1100);
    await login(email, 'Wrong1!!');
    const local = await getLocal();
    expect(local.failedLoginAttempts).to.equal(1);
    expect(local.lockedUntil).to.equal(undefined);
    expect((await login(email, password)).status).to.equal(200);
  });

  it('slows down one IP trying many usernames', async () => {
    // the tests above already failed 10 logins from this IP
    for (let i = 0; i < 20; i++) {
      await login(`user${i}@example.com`, 'Wrong1!!');
    }
    const start = Date.now();
    await login('another@example.com', 'Wrong1!!');
    expect(Date.now() - start).to.be.greaterThan(250);
  });
});
