'use strict';
import crypto from 'crypto';
import { EventEmitter } from 'events';
import { DocumentScope } from 'nano';
import { Config } from '../types/config';
import {
  CreateSessionOpts,
  LoginStartResult,
  MfaChallenge,
  MfaEnableResult,
  MfaSetupInfo,
  SlLoginSession,
  SlUserDoc
} from '../types/typings';
import { hashesEqual, hashToken } from '../util';
import { decryptSecret, encryptSecret, parseEncryptionKey } from './secret-box';
import {
  base32Decode,
  base32Encode,
  generateTotpSecret,
  otpauthUrl,
  totpStep,
  verifyTotp
} from './totp';

/** The parts of `User` the MFA flows need (all public there). */
export interface MfaUserAccess {
  userDB: DocumentScope<SlUserDoc>;
  emitter: EventEmitter;
  getUser(login: string, allowUUID?: boolean): Promise<SlUserDoc | null>;
  createSession(params: CreateSessionOpts): Promise<SlLoginSession>;
  registerFailedLogin(userDoc: SlUserDoc): Promise<void>;
  getLockedUntil(userDoc: SlUserDoc): number | undefined;
  logoutAllSessions(userDoc: SlUserDoc, reason: string): Promise<SlUserDoc>;
}

/** Same answer for every failure: no oracle on tokens, codes or locks. */
export const mfaInvalidError = {
  error: 'Unauthorized',
  message: 'Invalid or expired code',
  status: 401
};

const RECOVERY_CODE_BYTES = 7; // 56 bits, printed as 11-12 base32 characters

/**
 * Second factor (TOTP) flows. A session is created only after the second
 * factor: `startLogin` returns a short-lived token instead, which is neither a
 * session nor a CouchDB credential.
 */
export class MfaManager {
  private readonly key: Buffer | undefined;

  constructor(private config: Config, private user: MfaUserAccess) {
    this.key = config.mfa?.enabled
      ? parseEncryptionKey(config.mfa.encryptionKey)
      : undefined;
  }

  get enabled(): boolean {
    return this.config.mfa?.enabled === true;
  }

  /** Whether a session for this user needs a verified second factor */
  isRequiredFor(userDoc: SlUserDoc): boolean {
    if (!this.enabled) {
      return false;
    }
    return userDoc.mfa?.enabled === true || this.config.mfa.required === true;
  }

  /**
   * Call after the password check succeeded. Returns a session when no second
   * factor is needed, otherwise an `mfaToken` (or a `setupToken` when MFA is
   * required but the user has not enrolled yet).
   * @param userId the `_id` (UUID without hyphens) of the user
   */
  async startLogin(
    userId: string,
    opts: { provider?: string; sessionType?: string } = {}
  ): Promise<LoginStartResult> {
    const provider = opts.provider ?? 'local';
    const userDoc = await this.getUserById(userId);
    if (!this.isRequiredFor(userDoc)) {
      const session = await this.user.createSession({
        login: userDoc._id,
        provider,
        byUUID: true,
        sessionType: opts.sessionType
      });
      return { mfaRequired: false, mfaSetupRequired: false, session };
    }
    const kind = userDoc.mfa?.enabled ? 'login' : 'setup';
    const { token, expires } = await this.issueChallenge(userDoc, {
      kind,
      provider,
      sessionType: opts.sessionType
    });
    this.user.emitter.emit('mfa-challenge', userDoc.key, kind);
    if (kind === 'login') {
      return { mfaRequired: true, mfaSetupRequired: false, mfaToken: token, expires };
    }
    return { mfaRequired: false, mfaSetupRequired: true, setupToken: token, expires };
  }

  /**
   * Second login step: checks a TOTP code or an unused recovery code and
   * creates the session. Wrong codes count towards the account lockout.
   */
  async verifyLogin(mfaToken: string, code: string): Promise<SlLoginSession> {
    const { userDoc, tokenHash, challenge } = await this.resolveChallenge(mfaToken, 'login');
    const secret = this.decrypt(userDoc.mfa.secret);
    const now = Date.now();
    const step = verifyTotp(
      secret,
      code,
      now,
      this.config.mfa.window ?? 1,
      userDoc.mfa.lastUsedStep
    );
    let usedRecoveryCode = false;
    if (step === undefined) {
      usedRecoveryCode = this.consumeRecoveryCode(userDoc, code);
      if (!usedRecoveryCode) {
        await this.registerFailure(userDoc, tokenHash, challenge);
        throw mfaInvalidError;
      }
    } else {
      userDoc.mfa.lastUsedStep = step;
    }
    delete userDoc.mfa.challenges[tokenHash];
    await this.user.userDB.insert(userDoc);
    this.user.emitter.emit('mfa-verified', userDoc.key, usedRecoveryCode ? 'recovery' : 'totp');
    if (usedRecoveryCode) {
      this.user.emitter.emit(
        'mfa-recovery-code-used',
        userDoc.key,
        userDoc.mfa.recoveryCodes?.length ?? 0
      );
    }
    return this.user.createSession({
      login: userDoc._id,
      provider: challenge.provider,
      byUUID: true,
      sessionType: challenge.sessionType,
      mfaVerified: true
    });
  }

  /**
   * Starts an enrolment: generates a new secret, kept pending until
   * `enable` confirms it with a code.
   * @param target `setupToken` from `startLogin`, or `login` of an already
   * authenticated user (the caller is responsible for that check).
   */
  async beginSetup(target: { setupToken?: string; login?: string }): Promise<MfaSetupInfo> {
    this.assertEnabled();
    const userDoc = target.setupToken
      ? (await this.resolveChallenge(target.setupToken, 'setup')).userDoc
      : await this.getUserByLogin(target.login);
    const secret = generateTotpSecret();
    const expires = Date.now() + this.tokenLifeMs();
    userDoc.mfa = { ...(userDoc.mfa ?? { enabled: false }) };
    userDoc.mfa.pendingSecret = encryptSecret(secret, this.key);
    userDoc.mfa.pendingExpires = expires;
    await this.user.userDB.insert(userDoc);
    const secretBase32 = base32Encode(secret);
    const account = userDoc.email ?? userDoc.key;
    return {
      otpauthUrl: otpauthUrl(this.config.mfa.issuer, account, secretBase32),
      secret: secretBase32,
      expires
    };
  }

  /**
   * Confirms the enrolment with a code from the authenticator app, enables
   * MFA and returns new recovery codes. With a `setupToken`, the login is
   * completed and the session returned as well.
   */
  async enable(target: {
    setupToken?: string;
    login?: string;
    code: string;
  }): Promise<MfaEnableResult> {
    this.assertEnabled();
    let userDoc: SlUserDoc;
    let tokenHash: string | undefined;
    let challenge: MfaChallenge | undefined;
    if (target.setupToken) {
      ({ userDoc, tokenHash, challenge } = await this.resolveChallenge(
        target.setupToken,
        'setup'
      ));
    } else {
      userDoc = await this.getUserByLogin(target.login);
    }
    const mfa = userDoc.mfa;
    if (!mfa?.pendingSecret || !mfa.pendingExpires || mfa.pendingExpires < Date.now()) {
      if (challenge) {
        await this.registerFailure(userDoc, tokenHash, challenge);
      }
      throw mfaInvalidError;
    }
    const secret = this.decrypt(mfa.pendingSecret);
    const step = verifyTotp(secret, target.code, Date.now(), this.config.mfa.window ?? 1);
    if (step === undefined) {
      if (challenge) {
        await this.registerFailure(userDoc, tokenHash, challenge);
      } else {
        await this.user.registerFailedLogin(userDoc);
      }
      throw mfaInvalidError;
    }
    const recoveryCodes = this.generateRecoveryCodes();
    userDoc.mfa = {
      enabled: true,
      enabledAt: Date.now(),
      secret: mfa.pendingSecret,
      lastUsedStep: step,
      recoveryCodes: recoveryCodes.map(hashRecoveryCode),
      challenges: mfa.challenges ?? {}
    };
    if (tokenHash) {
      delete userDoc.mfa.challenges[tokenHash];
    }
    await this.user.userDB.insert(userDoc);
    this.user.emitter.emit('mfa-enabled', userDoc.key);
    const result: MfaEnableResult = { recoveryCodes };
    if (challenge) {
      result.session = await this.user.createSession({
        login: userDoc._id,
        provider: challenge.provider,
        byUUID: true,
        sessionType: challenge.sessionType,
        mfaVerified: true
      });
    }
    return result;
  }

  /**
   * Removes the second factor (e.g. lost device, done by an administrator)
   * and logs out all sessions of the user.
   */
  async reset(login: string): Promise<void> {
    let userDoc = await this.getUserByLogin(login);
    delete userDoc.mfa;
    userDoc = await this.user.logoutAllSessions(userDoc, 'mfa-reset');
    await this.user.userDB.insert(userDoc);
    this.user.emitter.emit('mfa-reset', userDoc.key);
  }

  /** Replaces the recovery codes; the old ones stop working. */
  async regenerateRecoveryCodes(login: string): Promise<string[]> {
    const userDoc = await this.getUserByLogin(login);
    if (!userDoc.mfa?.enabled) {
      throw { error: 'Bad Request', message: 'MFA is not enabled', status: 400 };
    }
    const codes = this.generateRecoveryCodes();
    userDoc.mfa.recoveryCodes = codes.map(hashRecoveryCode);
    await this.user.userDB.insert(userDoc);
    this.user.emitter.emit('mfa-recovery-codes-regenerated', userDoc.key);
    return codes;
  }

  // --- internals

  private assertEnabled() {
    if (!this.enabled) {
      throw { error: 'Bad Request', message: 'MFA is not enabled', status: 400 };
    }
  }

  private tokenLifeMs(): number {
    return (this.config.mfa.tokenLife ?? 300) * 1000;
  }

  private decrypt(boxed: string | undefined): Buffer {
    if (!boxed) {
      throw mfaInvalidError;
    }
    return decryptSecret(boxed, this.key);
  }

  private async getUserById(userId: string): Promise<SlUserDoc> {
    const userDoc = await this.findById(userId);
    if (!userDoc) {
      throw mfaInvalidError;
    }
    return userDoc;
  }

  /** `_id` is the UUID without hyphens */
  private async findById(userId: string): Promise<SlUserDoc | null> {
    if (!/^[0-9a-f]{32}$/.test(userId)) {
      return null;
    }
    try {
      return await this.user.userDB.get(userId);
    } catch (err) {
      if (err?.statusCode === 404) {
        return null;
      }
      throw err;
    }
  }

  private async getUserByLogin(login: string | undefined): Promise<SlUserDoc> {
    const userDoc = login ? await this.user.getUser(login, true) : null;
    if (!userDoc) {
      throw { error: 'Bad Request', message: 'User not found', status: 404 };
    }
    return userDoc;
  }

  private async issueChallenge(
    userDoc: SlUserDoc,
    challenge: Omit<MfaChallenge, 'expires' | 'attempts'>
  ): Promise<{ token: string; expires: number }> {
    // `<user _id>.<256 random bits>`: the id finds the document, only the hash is stored
    const token = `${userDoc._id}.${crypto.randomBytes(32).toString('base64url')}`;
    const expires = Date.now() + this.tokenLifeMs();
    userDoc.mfa = { ...(userDoc.mfa ?? { enabled: false }) };
    userDoc.mfa.challenges = pruneChallenges(userDoc.mfa.challenges);
    userDoc.mfa.challenges[hashToken(token)] = { ...challenge, expires, attempts: 0 };
    await this.user.userDB.insert(userDoc);
    return { token, expires };
  }

  private async resolveChallenge(
    token: string,
    kind: MfaChallenge['kind']
  ): Promise<{ userDoc: SlUserDoc; tokenHash: string; challenge: MfaChallenge }> {
    this.assertEnabled();
    const [userId, secret] = typeof token === 'string' ? token.split('.') : [];
    if (!userId || !secret) {
      throw mfaInvalidError;
    }
    const userDoc = await this.findById(userId);
    const challenges = userDoc?.mfa?.challenges ?? {};
    const tokenHash = hashToken(token);
    const storedHash = Object.keys(challenges).find(hash => hashesEqual(hash, tokenHash));
    const challenge = storedHash ? challenges[storedHash] : undefined;
    if (
      !userDoc ||
      !challenge ||
      challenge.kind !== kind ||
      challenge.expires < Date.now() ||
      this.user.getLockedUntil(userDoc)
    ) {
      throw mfaInvalidError;
    }
    return { userDoc, tokenHash: storedHash, challenge };
  }

  /** Counts a wrong code on the token and on the account lockout */
  private async registerFailure(
    userDoc: SlUserDoc,
    tokenHash: string,
    challenge: MfaChallenge
  ): Promise<void> {
    challenge.attempts += 1;
    if (challenge.attempts >= (this.config.mfa.maxAttempts ?? 5)) {
      delete userDoc.mfa.challenges[tokenHash];
    } else {
      userDoc.mfa.challenges[tokenHash] = challenge;
    }
    this.user.emitter.emit('mfa-failed', userDoc.key, challenge.attempts);
    if (userDoc.local && this.hasLockout()) {
      // registerFailedLogin saves the document, challenge counters included
      await this.user.registerFailedLogin(userDoc);
    } else {
      await this.user.userDB.insert(userDoc);
    }
  }

  private hasLockout(): boolean {
    return Boolean(this.config.security?.maxFailedLogins);
  }

  private consumeRecoveryCode(userDoc: SlUserDoc, code: string): boolean {
    const hashes = userDoc.mfa.recoveryCodes ?? [];
    const given = hashRecoveryCode(code);
    let index = -1;
    hashes.forEach((hash, i) => {
      if (hashesEqual(hash, given) && index === -1) {
        index = i;
      }
    });
    if (index === -1) {
      return false;
    }
    hashes.splice(index, 1);
    userDoc.mfa.recoveryCodes = hashes;
    return true;
  }

  private generateRecoveryCodes(): string[] {
    const count = this.config.mfa.recoveryCodeCount ?? 10;
    return Array.from({ length: count }, () => {
      const raw = base32Encode(crypto.randomBytes(RECOVERY_CODE_BYTES)).slice(0, 10);
      return `${raw.slice(0, 5)}-${raw.slice(5)}`;
    });
  }
}

/** Recovery codes are compared case- and separator-insensitively */
export function hashRecoveryCode(code: string): string {
  const normalized = typeof code === 'string' ? code.toUpperCase().replace(/[^A-Z2-7]/g, '') : '';
  return hashToken(`recovery:${normalized}`);
}

function pruneChallenges(
  challenges: Record<string, MfaChallenge> | undefined
): Record<string, MfaChallenge> {
  const now = Date.now();
  return Object.fromEntries(
    Object.entries(challenges ?? {}).filter(([, c]) => c.expires > now)
  );
}

// re-exported for tests and tooling
export { base32Decode, totpStep };
