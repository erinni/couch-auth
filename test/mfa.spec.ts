import { expect } from 'chai';
import crypto from 'crypto';
import express from 'express';
import http from 'http';
import nano from 'nano';
import request from 'superagent';
import { ConfigHelper } from '../lib/config/configure';
import { CouchAuth } from '../lib/index';
import { decryptSecret, encryptSecret, parseEncryptionKey } from '../lib/mfa/secret-box';
import {
  base32Decode,
  base32Encode,
  hotp,
  totpCode,
  totpStep,
  verifyTotp
} from '../lib/mfa/totp';
import { getDBURL, timeoutPromise } from '../lib/util';
import { config as baseConfig } from './test.config';

const ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64');

describe('MFA: TOTP primitives', function () {
  const rfcSecret = Buffer.from('12345678901234567890', 'ascii');

  it('matches the RFC 6238 SHA-1 test vectors (last 6 digits)', function () {
    // RFC 6238 appendix B: 94287082, 07081804, 89005924
    expect(hotp(rfcSecret, totpStep(59 * 1000))).to.equal('287082');
    expect(hotp(rfcSecret, totpStep(1111111109 * 1000))).to.equal('081804');
    expect(hotp(rfcSecret, totpStep(1234567890 * 1000))).to.equal('005924');
    expect(hotp(rfcSecret, totpStep(59 * 1000), 8)).to.equal('94287082');
  });

  it('encodes and decodes base32 (RFC 4648)', function () {
    expect(base32Encode(Buffer.from('foobar'))).to.equal('MZXW6YTBOI');
    expect(base32Decode('MZXW6YTBOI').toString()).to.equal('foobar');
    expect(base32Decode('mzxw 6ytb oi').toString()).to.equal('foobar');
  });

  it('accepts codes within the window and refuses replays', function () {
    const now = 1_700_000_000_000;
    const step = totpStep(now);
    const code = totpCode(rfcSecret, now);
    expect(verifyTotp(rfcSecret, code, now, 1)).to.equal(step);
    expect(verifyTotp(rfcSecret, code, now + 30_000, 1)).to.equal(step);
    expect(verifyTotp(rfcSecret, code, now + 90_000, 1)).to.equal(undefined);
    expect(verifyTotp(rfcSecret, code, now, 1, step)).to.equal(undefined);
    expect(verifyTotp(rfcSecret, 'abcdef', now, 1)).to.equal(undefined);
    expect(verifyTotp(rfcSecret, '12345', now, 1)).to.equal(undefined);
  });

  it('encrypts secrets with AES-256-GCM and detects tampering', function () {
    const key = parseEncryptionKey(ENCRYPTION_KEY);
    const plain = crypto.randomBytes(20);
    const boxed = encryptSecret(plain, key);
    expect(boxed.startsWith('v1.')).to.equal(true);
    expect(decryptSecret(boxed, key).equals(plain)).to.equal(true);
    const tampered = boxed.slice(0, -2) + (boxed.endsWith('A') ? 'BB' : 'AA');
    expect(() => decryptSecret(tampered, key)).to.throw();
    expect(() => parseEncryptionKey('too-short')).to.throw();
  });

  it('validates the MFA configuration', function () {
    const base = { ...baseConfig, security: { ...baseConfig.security } };
    expect(() => new ConfigHelper({ ...base, mfa: { enabled: true, issuer: 'X' } } as any)).to.throw(
      /encryptionKey/
    );
    expect(
      () =>
        new ConfigHelper({
          ...base,
          security: { ...base.security, loginOnPasswordReset: true },
          mfa: { enabled: true, issuer: 'X', encryptionKey: ENCRYPTION_KEY }
        } as any)
    ).to.throw(/loginOnPasswordReset/);
    expect(
      () =>
        new ConfigHelper({
          ...base,
          mfa: { enabled: true, required: true, issuer: 'X', encryptionKey: ENCRYPTION_KEY }
        } as any)
    ).to.throw(/OAuth/);
  });
});

describe('MFA: login flows', function () {
  this.timeout(30000);

  const port = 5002;
  const server = `http://localhost:${port}`;
  const userDBName = 'sl_test-mfa-users';
  const keysDBName = 'sl_test-mfa-keys';
  const couch = nano(getDBURL(baseConfig.dbServer));
  const password = 'Password1!';
  const email = 'mfa@example.com';
  let couchAuth: CouchAuth;
  let httpServer: http.Server;
  let totpSecret: Buffer;
  let recoveryCodes: string[];

  const config = {
    ...baseConfig,
    providers: {},
    dbServer: { ...baseConfig.dbServer, userDB: userDBName, couchAuthDB: keysDBName },
    local: {
      sendConfirmEmail: false,
      requireEmailConfirm: false,
      emailUsername: true,
      usernameLogin: false
    },
    security: {
      ...baseConfig.security,
      maxFailedLogins: 8,
      lockoutTime: 2,
      loginRateLimit: { delayAfter: 100 },
      loginRateLimitPerIp: { delayAfter: 100 },
      userHashing: { iterations: 1000 }
    },
    mfa: {
      enabled: true,
      required: true,
      issuer: 'CouchAuth Test',
      encryptionKey: ENCRYPTION_KEY,
      maxAttempts: 3
    }
  };

  const post = (path: string, body: object) =>
    request
      .post(`${server}/auth${path}`)
      .send(body)
      .then(
        res => res,
        err => err.response
      );

  const login = () => post('/login', { username: email, password });

  const userDoc = async () => couchAuth.getUser(email);

  const sessionKeysCount = async () =>
    (await couch.use(keysDBName).list()).rows.filter(r => !r.id.startsWith('_design/')).length;

  /** A valid code for the step after the last used one (refused replays) */
  const nextCode = async () => {
    const doc = await userDoc();
    const step = Math.max(totpStep(Date.now()), (doc.mfa?.lastUsedStep ?? 0) + 1);
    return hotp(totpSecret, step);
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
    const app = express();
    app.use(express.json());
    app.use('/auth', couchAuth.router);
    app.get('/protected', couchAuth.requireAuth, (_req, res) => {
      res.json({ ok: true });
    });
    httpServer = app.listen(port);
    await couchAuth.createUser({ email, password, confirmPassword: password });
    for (let i = 0; i < 50 && !(await userDoc()); i++) {
      await timeoutPromise(100);
    }
  });

  after(async () => {
    httpServer.close();
    await couch.db.destroy(userDBName);
    await couch.db.destroy(keysDBName);
  });

  it('returns a setupToken and no session when MFA is required but not enrolled', async () => {
    const before = await sessionKeysCount();
    const res = await login();
    expect(res.status).to.equal(200);
    expect(res.body.mfaSetupRequired).to.equal(true);
    expect(res.body.setupToken).to.be.a('string');
    expect(res.body).not.to.have.property('token');
    expect(res.body).not.to.have.property('password');
    expect(await sessionKeysCount()).to.equal(before);
  });

  it('refuses to create a session without the second factor', async () => {
    const doc = await userDoc();
    let error: any;
    try {
      await couchAuth.createSession({ login: doc._id, provider: 'local', byUUID: true });
    } catch (err) {
      error = err;
    }
    expect(error?.status).to.equal(401);
  });

  it('enrols with setup token and code, returning recovery codes and a session', async () => {
    const { body } = await login();
    const setup = await post('/mfa/setup', { setupToken: body.setupToken });
    expect(setup.status).to.equal(200);
    expect(setup.body.otpauthUrl).to.match(/^otpauth:\/\/totp\/CouchAuth%20Test%3Amfa%40example\.com\?/);
    totpSecret = base32Decode(setup.body.secret);

    const stored = await userDoc();
    expect(stored.mfa.pendingSecret.startsWith('v1.')).to.equal(true);
    expect(JSON.stringify(stored)).not.to.contain(setup.body.secret);

    const wrong = await post('/mfa/enable', { setupToken: body.setupToken, code: '000000' });
    expect(wrong.status).to.equal(401);

    const enabled = await post('/mfa/enable', {
      setupToken: body.setupToken,
      code: totpCode(totpSecret, Date.now())
    });
    expect(enabled.status).to.equal(200);
    expect(enabled.body.recoveryCodes).to.have.length(10);
    expect(enabled.body.session.token).to.be.a('string');
    recoveryCodes = enabled.body.recoveryCodes;

    const doc = await userDoc();
    expect(doc.mfa.enabled).to.equal(true);
    expect(doc.mfa.pendingSecret).to.equal(undefined);
    expect(doc.mfa.recoveryCodes).to.have.length(10);
    expect(doc.mfa.recoveryCodes).not.to.include(recoveryCodes[0]);

    // the setup token was consumed
    const reuse = await post('/mfa/enable', { setupToken: body.setupToken, code: await nextCode() });
    expect(reuse.status).to.equal(401);
  });

  it('asks for the code on login and refuses the same code twice', async () => {
    const first = await login();
    expect(first.body.mfaRequired).to.equal(true);
    expect(first.body).not.to.have.property('token');
    const code = await nextCode();
    const ok = await post('/login/mfa', { mfaToken: first.body.mfaToken, code });
    expect(ok.status).to.equal(200);
    expect(ok.body.token).to.be.a('string');
    const bearer = `Bearer ${ok.body.token}:${ok.body.password}`;
    const protectedRes = await request.get(`${server}/protected`).set('Authorization', bearer);
    expect(protectedRes.status).to.equal(200);

    const second = await login();
    const replay = await post('/login/mfa', { mfaToken: second.body.mfaToken, code });
    expect(replay.status).to.equal(401);
  });

  it('does not accept the mfaToken as a bearer session', async () => {
    const { body } = await login();
    const res = await request
      .get(`${server}/protected`)
      .set('Authorization', `Bearer ${body.mfaToken}`)
      .then(
        r => r,
        err => err.response
      );
    expect(res.status).to.equal(401);
  });

  it('accepts each recovery code once', async () => {
    const first = await login();
    const ok = await post('/login/mfa', {
      mfaToken: first.body.mfaToken,
      code: recoveryCodes[0].toLowerCase()
    });
    expect(ok.status).to.equal(200);
    const second = await login();
    const again = await post('/login/mfa', {
      mfaToken: second.body.mfaToken,
      code: recoveryCodes[0]
    });
    expect(again.status).to.equal(401);
    expect((await userDoc()).mfa.recoveryCodes).to.have.length(9);
  });

  it('invalidates the token after maxAttempts wrong codes', async () => {
    const { body } = await login();
    for (let i = 0; i < 3; i++) {
      const res = await post('/login/mfa', { mfaToken: body.mfaToken, code: '000000' });
      expect(res.status).to.equal(401);
    }
    const res = await post('/login/mfa', { mfaToken: body.mfaToken, code: await nextCode() });
    expect(res.status).to.equal(401);
  });

  it('counts wrong codes towards the account lockout', async () => {
    await timeoutPromise(2100); // lockoutTime: previous failures expire
    let locked = false;
    couchAuth.emitter.once('login-locked', () => {
      locked = true;
    });
    for (let round = 0; round < 3; round++) {
      const { body } = await login();
      for (let i = 0; i < 3; i++) {
        await post('/login/mfa', { mfaToken: body.mfaToken, code: '000000' });
      }
    }
    // 9 wrong codes > maxFailedLogins (8): the right password is refused now
    const res = await login();
    expect(res.status).to.equal(401);
    expect(locked).to.equal(true);
    await timeoutPromise(2100);
  });

  it('rejects expired tokens', async () => {
    const shortAuth = new CouchAuth({ ...config, mfa: { ...config.mfa, tokenLife: 1 } } as any);
    const doc = await userDoc();
    const result: any = await shortAuth.startLogin(doc._id);
    expect(result.mfaRequired).to.equal(true);
    await timeoutPromise(1200);
    let error: any;
    try {
      await shortAuth.verifyMfaLogin(result.mfaToken, await nextCode());
    } catch (err) {
      error = err;
    }
    expect(error?.status).to.equal(401);
  });

  it('resets MFA and logs out all sessions', async () => {
    const first = await login();
    const ok = await post('/login/mfa', { mfaToken: first.body.mfaToken, code: await nextCode() });
    const bearer = `Bearer ${ok.body.token}:${ok.body.password}`;
    await couchAuth.resetMfa(email);
    expect((await userDoc()).mfa).to.equal(undefined);
    const res = await request
      .get(`${server}/protected`)
      .set('Authorization', bearer)
      .then(
        r => r,
        err => err.response
      );
    expect(res.status).to.equal(401);
    // required: the next login asks for a new enrolment
    expect((await login()).body.mfaSetupRequired).to.equal(true);
  });
});

describe('MFA: optional mode', function () {
  this.timeout(30000);

  const userDBName = 'sl_test-mfa-opt-users';
  const keysDBName = 'sl_test-mfa-opt-keys';
  const couch = nano(getDBURL(baseConfig.dbServer));
  const email = 'mfa-opt@example.com';
  const password = 'Password1!';
  let couchAuth: CouchAuth;

  before(async () => {
    await couch.db.create(userDBName);
    await couch.db.create(keysDBName);
    couchAuth = new CouchAuth({
      ...baseConfig,
      providers: {},
      dbServer: { ...baseConfig.dbServer, userDB: userDBName, couchAuthDB: keysDBName },
      local: { sendConfirmEmail: false, requireEmailConfirm: false, emailUsername: true },
      mfa: { enabled: true, issuer: 'CouchAuth Test', encryptionKey: ENCRYPTION_KEY }
    } as any);
    const userDB = couch.use(userDBName);
    for (let i = 0; i < 50; i++) {
      try {
        await userDB.get('_design/auth');
        break;
      } catch {
        await timeoutPromise(100);
      }
    }
    await couchAuth.createUser({ email, password, confirmPassword: password });
    for (let i = 0; i < 50 && !(await couchAuth.getUser(email)); i++) {
      await timeoutPromise(100);
    }
  });

  after(async () => {
    await couch.db.destroy(userDBName);
    await couch.db.destroy(keysDBName);
  });

  it('creates the session directly for users without MFA', async () => {
    const doc = await couchAuth.getUser(email);
    const result: any = await couchAuth.startLogin(doc._id);
    expect(result.mfaRequired).to.equal(false);
    expect(result.session.token).to.be.a('string');
  });

  it('lets an authenticated user enable MFA by login, then requires it', async () => {
    const info = await couchAuth.beginMfaSetup({ login: email });
    const secret = base32Decode(info.secret);
    const result = await couchAuth.enableMfa({ login: email, code: totpCode(secret, Date.now()) });
    expect(result.recoveryCodes).to.have.length(10);
    expect(result.session).to.equal(undefined);
    const doc = await couchAuth.getUser(email);
    const next: any = await couchAuth.startLogin(doc._id);
    expect(next.mfaRequired).to.equal(true);
    const codes = await couchAuth.regenerateMfaRecoveryCodes(email);
    expect(codes).to.have.length(10);
    expect(codes).not.to.include(result.recoveryCodes[0]);
  });
});
