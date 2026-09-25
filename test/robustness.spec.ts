import { expect } from 'chai';
import nano from 'nano';
import sinon from 'sinon';
import { CouchAuth } from '../lib/index';
import { getDBURL, timeoutPromise } from '../lib/util';
import { config as baseConfig } from './test.config';

describe('Robustness', function () {
  this.timeout(30000);

  const userDBName = 'sl_test-robust-users';
  const keysDBName = 'sl_test-robust-keys';
  const couch = nano(getDBURL(baseConfig.dbServer));
  const password = 'Password1!';
  let couchAuth: CouchAuth;
  let unhandled: unknown[];
  const onUnhandled = (reason: unknown) => unhandled.push(reason);

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

  const createUser = async (email: string) => {
    const signedUp = new Promise(resolve =>
      couchAuth.emitter.once('signup', resolve)
    );
    await couchAuth.createUser({ email, password, confirmPassword: password });
    await signedUp;
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
    await createUser('existing@example.com');
  });

  after(async () => {
    await couch.db.destroy(userDBName);
    await couch.db.destroy(keysDBName);
  });

  beforeEach(() => {
    unhandled = [];
    process.on('unhandledRejection', onUnhandled);
  });

  afterEach(() => {
    process.removeListener('unhandledRejection', onUnhandled);
    sinon.restore();
  });

  it('emits signup-error instead of an unhandled rejection when the insert fails', async () => {
    sinon
      .stub(couchAuth as any, 'insertNewUserDocument')
      .rejects(new Error('CouchDB down'));
    const signupError = new Promise(resolve =>
      couchAuth.emitter.once('signup-error', (_user, err) => resolve(err))
    );
    const result = await couchAuth.createUser({
      email: 'new@example.com',
      password,
      confirmPassword: password
    });
    expect(result).to.have.property('_id');
    expect(((await signupError) as Error).message).to.equal('CouchDB down');
    await timeoutPromise(50);
    expect(unhandled).to.deep.equal([]);
  });

  it('does not reject unhandled when the "email exists" mail fails', async () => {
    sinon.stub((couchAuth as any).mailer, 'sendEmail').rejects(new Error('SMTP down'));
    const result = await couchAuth.createUser({
      email: 'existing@example.com',
      password,
      confirmPassword: password
    });
    expect(result).to.equal(undefined);
    await timeoutPromise(200);
    expect(unhandled).to.deep.equal([]);
  });

  it('does not reject unhandled when the email change fails in background', async () => {
    sinon
      .stub(couchAuth as any, 'completeEmailChange')
      .rejects({ error: 'Bad Request', status: 400 });
    await couchAuth.changeEmail('existing@example.com', 'other@example.com', {});
    await timeoutPromise(50);
    expect(unhandled).to.deep.equal([]);
  });

  it('rejects forgotPassword without an email with 400', async () => {
    const err = await couchAuth.forgotPassword(undefined, {}).catch(e => e);
    expect(err).to.deep.equal({ error: 'invalid email', status: 400 });
  });

  it('rejects refreshSession for an unknown session with 401', async () => {
    const err = await couchAuth.refreshSession('unknownsession').catch(e => e);
    expect(err).to.deep.equal({ error: 'Unauthorized', status: 401 });
  });
});
