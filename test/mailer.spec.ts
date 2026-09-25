'use strict';
import { expect } from 'chai';
import { join } from 'path';
import sinon from 'sinon';
import { ConfigHelper as Configure } from '../src/config/configure';
import { Mailer } from '../src/mailer';

const mailerTestConfig = new Configure({
  testMode: {
    noEmail: true
  },
  mailer: {
    fromEmail: 'noreply@example.com',
    retryOnError: {
      maxRetries: 3,
      initialBackoffSeconds: 0.1
    }
  },
  emailTemplates: {
    folder: join(__dirname, '../templates/email'),
    data: { baseUrl: 'https://example.com/' }
  }
});

const req = {
  protocol: 'https',
  headers: {
    host: 'attacker.example'
  }
};

const user = {
  name: 'Super',
  unverifiedEmail: {
    token: 'abc123'
  }
};

const mailer = new Mailer(mailerTestConfig.config);

describe('Mailer', function () {
  it('should send a confirmation email', function () {
    return mailer
      .sendEmail('confirmEmail', 'super@example.com', {
        req,
        user
      })
      .then(function (result) {
        const response = result.response.toString();
        expect(response.search('From: noreply@example.com')).to.be.greaterThan(
          -1
        );
        expect(response.search('To: super@example.com')).to.be.greaterThan(-1);
        expect(
          response.search('Subject: Please confirm your email')
        ).to.be.greaterThan(-1);
        expect(response.search('Hi Super,')).to.be.greaterThan(-1);
        expect(
          response.search('https://example.com/auth/confirm-email/abc123')
        ).to.be.greaterThan(-1);
        // links never come from the request's Host header
        expect(response).not.to.include('attacker.example');
      });
  });

  it('should render all default templates', async () => {
    const data = {
      req,
      user
    };
    let templateCount = 0;
    for (const template of Object.keys(
      mailerTestConfig.config.emailTemplates.templates
    )) {
      const res = await mailer.sendEmail(template, 'super@example.com', data);
      expect(
        res.response
          .toString()
          .search(`${new Date().getFullYear()} Fynn Leitow`)
      ).to.be.greaterThan(-1);

      templateCount += 1;
    }
    expect(templateCount).to.be.equal(6);
  });

  it('should retry 3x on error', async () => {
    mailer['transporter']['sendMail'] = x => {
      throw 'nope';
    };
    const spySendMail = sinon.spy(mailer['transporter'], 'sendMail');
    try {
      let res = await mailer.sendEmail('confirmEmail', 'super@example.com', {
        req,
        user
      });
    } catch (error) {
      expect(error).to.equal('nope');
    }
    expect(spySendMail.callCount).to.equal(4);
  });

  it('should retry when sending rejects', async () => {
    let calls = 0;
    mailer['transporter']['sendMail'] = (async () => {
      calls += 1;
      if (calls === 1) {
        throw 'nope';
      }
      return 'sent';
    }) as any;
    const res = await mailer.sendEmail('confirmEmail', 'super@example.com', {
      req,
      user
    });
    expect(res).to.equal('sent');
    expect(calls).to.equal(2);
  });

  it('requires a baseUrl to send the default templates', () => {
    const base = {
      mailer: { fromEmail: 'noreply@example.com' },
      emailTemplates: {}
    };
    expect(() => new Configure(base)).to.throw(/baseUrl/);
    expect(
      () =>
        new Configure({
          ...base,
          emailTemplates: { data: { baseUrl: 'example.com' } }
        })
    ).to.throw(/baseUrl/);
    expect(
      () =>
        new Configure({
          ...base,
          emailTemplates: { data: { baseUrl: 'https://example.com' } }
        })
    ).not.to.throw();
    expect(
      () =>
        new Configure({
          ...base,
          mailer: { ...base.mailer, useCustomMailer: true }
        })
    ).not.to.throw();
  });

  it('keeps the config of each instance separate', () => {
    const first = new Configure({
      security: { maxFailedLogins: 3 },
      testMode: { noEmail: true }
    });
    const second = new Configure({ testMode: { noEmail: true } });
    expect(first.config.security.maxFailedLogins).to.equal(3);
    expect(second.config.security.maxFailedLogins).to.equal(undefined);
  });
});
