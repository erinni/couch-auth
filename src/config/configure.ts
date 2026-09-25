'use strict';
import { Config } from '../types/config';
import { mergeConfig } from '../util';
import { defaultConfig } from './default.config';

export class ConfigHelper {
  // a copy: merging into `defaultConfig` would carry one instance's settings
  // over to the next one
  public config: Config = structuredClone(defaultConfig);

  constructor(data: Partial<Config> = {}) {
    // Some extra default settings if no config object is specified
    if (Object.keys(data).length === 0) {
      this.config.testMode = {
        noEmail: true,
        debugEmail: true
      };
    } else {
      this.config = mergeConfig(this.config, data);
      this.verifyConfig();
    }
  }

  /** Verifies the config against some incompatible settings */
  private verifyConfig() {
    if (
      this.config.local?.requireEmailConfirm &&
      !this.config.local.sendConfirmEmail
    ) {
      throw 'sendConfirmEmail must also be set if requireEmailConfirm is.';
    }
    if (
      this.config.local?.keepEmailConfirmToken &&
      !this.config.local.sendConfirmEmail
    ) {
      throw 'sendConfirmEmail must also be set if keepEmailConfirmToken is.';
    }

    this.verifyBaseUrl();

    if (this.config.security?.iterations) {
      const itArr = this.config.security.iterations;
      let prev = 0;
      for (const pair of itArr) {
        if (
          pair.length !== 2 ||
          typeof pair[0] !== 'number' ||
          typeof pair[1] !== 'number' ||
          pair[0] < prev
        ) {
          throw 'iterations are specified but have invalid format!';
        }
        prev = pair[0];
      }
    }
  }

  private verifyBaseUrl() {
    const baseUrl = this.config.emailTemplates?.data?.baseUrl;
    if (baseUrl !== undefined) {
      if (typeof baseUrl !== 'string' || !/^https?:\/\/[^/]+/.test(baseUrl)) {
        throw 'emailTemplates.data.baseUrl must be an absolute http(s) URL.';
      }
      this.config.emailTemplates.data.baseUrl = baseUrl.replace(/\/+$/, '');
      return;
    }
    const sendsDefaultTemplates =
      this.config.emailTemplates?.folder ===
        defaultConfig.emailTemplates.folder &&
      !this.config.mailer?.useCustomMailer &&
      !this.config.testMode?.noEmail;
    if (sendsDefaultTemplates) {
      throw 'emailTemplates.data.baseUrl must be set to send the default email templates.';
    }
  }
}
