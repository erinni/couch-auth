import { expect } from 'chai';
import nano from 'nano';
import sinon from 'sinon';
import { CouchAuth } from '../lib/index';
import { getDBURL, hashToken, timeoutPromise } from '../lib/util';
import { config as baseConfig } from './test.config';

describe('Email confirmation token', function () {
  this.timeout(30000);

  const userDBName = 'sl_test-emailtoken-users';
  const keysDBName = 'sl_test-emailtoken-keys';
  const couch = nano(getDBURL(baseConfig.dbServer));
  const userDB = couch.use<any>(userDBName);
  const password = 'Password1!';
  let couchAuth: CouchAuth;

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
    security: { ...baseConfig.security, userHashing: { iterations: 1000 } }
  };

  /** creates a user, returns its doc and the emailed token */
  const createUser = async (email: string) => {
    const signedUp = new Promise(resolve =>
      couchAuth.emitter.once('signup', resolve)
    );
    const emailed = new Promise<string>(resolve =>
      couchAuth.emitter.once('confirm-email-token', ({ token }) =>
        resolve(token)
      )
    );
    await couchAuth.createUser({ email, password, confirmPassword: password });
    await signedUp;
    return { token: await emailed, doc: await couchAuth.getUser(email) };
  };

  before(async () => {
    await couch.db.create(userDBName);
    await couch.db.create(keysDBName);
    couchAuth = new CouchAuth(config as any);
    for (let i = 0; i < 50; i++) {
      try {
        await userDB.get('_design/auth');
        break;
      } catch {
        await timeoutPromise(100);
      }
    }
  });

  after(async () => {
    await couch.db.destroy(userDBName);
    await couch.db.destroy(keysDBName);
  });

  afterEach(() => sinon.restore());

  it('stores only the hash and an expiry, and emails the token', async () => {
    const sendEmail = sinon.spy((couchAuth as any).mailer, 'sendEmail');
    const { token, doc } = await createUser('one@example.com');
    expect(doc.unverifiedEmail.token).to.equal(hashToken(token));
    expect(doc.unverifiedEmail.expires).to.be.greaterThan(Date.now());
    const [templateId, , data] = sendEmail.firstCall.args;
    expect(templateId).to.equal('confirmEmail');
    expect(data.user.unverifiedEmail.token).to.equal(token);
    expect(data.token).to.equal(token);
  });

  it('confirms the email with the emailed token', async () => {
    const { token } = await createUser('two@example.com');
    await couchAuth.verifyEmail(token);
    const doc = await couchAuth.getUser('two@example.com');
    expect(doc.email).to.equal('two@example.com');
    expect(doc.unverifiedEmail).to.equal(undefined);
  });

  it('does not accept the stored hash as a token', async () => {
    const { doc } = await createUser('three@example.com');
    const err = await couchAuth
      .verifyEmail(doc.unverifiedEmail.token)
      .catch(e => e);
    expect(err).to.deep.equal({ error: 'Invalid token', status: 400 });
  });

  it('rejects an expired token', async () => {
    const { token, doc } = await createUser('four@example.com');
    doc.unverifiedEmail.expires = Date.now() - 1000;
    await userDB.insert(doc);
    const err = await couchAuth.verifyEmail(token).catch(e => e);
    expect(err).to.deep.equal({ error: 'Token expired', status: 400 });
    expect((await couchAuth.getUser('four@example.com')).email).to.equal(
      undefined
    );
  });

  it('still accepts a plain token stored before hashing', async () => {
    const { doc } = await createUser('five@example.com');
    doc.unverifiedEmail = { email: 'five@example.com', token: 'oldplaintoken' };
    await userDB.insert(doc);
    await couchAuth.verifyEmail('oldplaintoken');
    expect((await couchAuth.getUser('five@example.com')).email).to.equal(
      'five@example.com'
    );
  });

  it('hashes the token of an email change too', async () => {
    const { token } = await createUser('six@example.com');
    await couchAuth.verifyEmail(token);
    const changeToken = new Promise<string>(resolve =>
      couchAuth.emitter.once('confirm-email-token', ({ token }) =>
        resolve(token)
      )
    );
    await couchAuth.changeEmail('six@example.com', 'seven@example.com', {});
    const newToken = await changeToken;
    await timeoutPromise(300); // the change is saved in background
    const doc = await couchAuth.getUser('six@example.com');
    expect(doc.unverifiedEmail.token).to.equal(hashToken(newToken));
    await couchAuth.verifyEmail(newToken);
    expect((await couchAuth.getUser('seven@example.com')).email).to.equal(
      'seven@example.com'
    );
  });
});
