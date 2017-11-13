import axios from 'axios';
import * as fs from 'fs';
import * as mime from 'mime';
import * as pify from 'pify';

const gp12pem = require('google-p12-pem');
const jws = require('jws');

const readFile = pify(fs.readFile);
const toPem = pify(gp12pem);

const GOOGLE_TOKEN_URL = 'https://accounts.google.com/o/oauth2/token';
const GOOGLE_REVOKE_TOKEN_URL =
    'https://accounts.google.com/o/oauth2/revoke?token=';

interface Payload {
  iss: string;
  scope: string|string[];
  aud: string;
  exp: number;
  iat: number;
  sub: string;
}

export interface TokenOptions {
  keyFile?: string;
  key?: string|undefined;
  email?: string|undefined;
  iss?: string;
  sub?: string;
  scope?: string|string[];
}

class ErrorWithCode extends Error {
  constructor(message: string, public code: string) {
    super(message);
  }
}

export class GoogleToken {
  token: string|null;
  expiresAt: number|null;
  key: string|undefined;
  keyFile: string|undefined;
  iss: string|undefined;
  sub: string;
  scope: string|undefined;
  rawToken: string|null;
  tokenExpires: number|null;
  email: string;

  /**
   * Create a GoogleToken.
   *
   * @param options  Configuration object.
   */
  constructor(options?: TokenOptions) {
    this.configure(options);
  }

  /**
   * Returns whether the token has expired.
   *
   * @return true if the token has expired, false otherwise.
   */
  hasExpired() {
    const now = (new Date()).getTime();
    if (this.token && this.expiresAt) {
      return now >= this.expiresAt;
    } else {
      return true;
    }
  }

  /**
   * Returns a cached token or retrieves a new one from Google.
   *
   * @param callback The callback function.
   */
  getToken(): Promise<string|null>;
  getToken(callback: (err: Error|null, token?: string|null) => void): void;
  getToken(callback?: (err: Error|null, token?: string|null) => void):
      void|Promise<string|null> {
    if (callback) {
      this.getTokenAsync()
          .then(t => {
            callback(null, t);
          })
          .catch(callback);
      return;
    }
    return this.getTokenAsync();
  }

  private async getTokenAsync() {
    if (!this.hasExpired()) {
      return Promise.resolve(this.token);
    }

    if (!this.key && !this.keyFile) {
      throw new Error('No key or keyFile set.');
    }

    if (!this.key && this.keyFile) {
      const mimeType = mime.getType(this.keyFile);
      switch (mimeType) {
        case 'application/json': {
          // *.json file
          const key = await readFile(this.keyFile, 'utf8');
          const body = JSON.parse(key);
          this.key = body.private_key;
          this.iss = body.client_email;
          if (!this.key || !this.iss) {
            throw new ErrorWithCode(
                'private_key and client_email are required.',
                'MISSING_CREDENTIALS');
          }
          break;
        }
        case 'application/x-x509-ca-cert': {
          // *.pem file
          this.ensureEmail();
          this.key = await readFile(this.keyFile, 'utf8');
          break;
        }
        case 'application/x-pkcs12': {
          // *.p12 file
          this.ensureEmail();
          this.key = await toPem(this.keyFile);
          break;
        }
        default:
          throw new ErrorWithCode(
              'Unknown certificate type. Type is determined based on file extension.  Current supported extensions are *.json, *.pem, and *.p12.',
              'UNKNOWN_CERTIFICATE_TYPE');
      }
    }
    return this.requestToken();
  }

  private ensureEmail() {
    if (!this.iss) {
      throw new ErrorWithCode('email is required.', 'MISSING_CREDENTIALS');
    }
  }

  /**
   * Revoke the token if one is set.
   *
   * @param callback The callback function.
   */
  revokeToken(): Promise<void>;
  revokeToken(callback: (err?: Error) => void): void;
  revokeToken(callback?: (err?: Error) => void): void|Promise<void> {
    if (callback) {
      this.revokeTokenAsync().then(() => callback()).catch(callback);
      return;
    }
    return this.revokeTokenAsync();
  }

  private async revokeTokenAsync() {
    if (!this.token) {
      throw new Error('No token to revoke.');
    }
    return axios.get(GOOGLE_REVOKE_TOKEN_URL + this.token).then(r => {
      this.configure({
        email: this.iss,
        sub: this.sub,
        key: this.key,
        keyFile: this.keyFile,
        scope: this.scope
      });
    });
  }


  /**
   * Configure the GoogleToken for re-use.
   * @param  {object} options Configuration object.
   */
  private configure(options: TokenOptions = {}) {
    this.keyFile = options.keyFile;
    this.key = options.key;
    this.token = this.expiresAt = this.rawToken = null;
    this.iss = options.email || options.iss;

    if (options.sub) {
      this.sub = options.sub;
    }

    if (typeof options.scope === 'object') {
      this.scope = options.scope.join(' ');
    } else {
      this.scope = options.scope;
    }
  }

  /**
   * Request the token from Google.
   *
   * @param  {Function} callback The callback function.
   */
  private async requestToken() {
    const iat = Math.floor(new Date().getTime() / 1000);
    const payload = {
      iss: this.iss,
      scope: this.scope,
      aud: GOOGLE_TOKEN_URL,
      exp: iat + 3600,  // 3600 seconds = 1 hour
      iat,
    } as Payload;

    if (this.sub) {
      payload.sub = this.sub;
    }

    const toSign = {
      header: {alg: 'RS256', typ: 'JWT'},
      payload,
      secret: this.key
    };

    const signedJWT = jws.sign(toSign);

    return axios
        .post(GOOGLE_TOKEN_URL, {
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion: signedJWT
        })
        .then(r => {
          const body = r.data;
          this.rawToken = body;
          this.token = body.access_token;
          this.expiresAt = (iat + body.expires_in) * 1000;
          return this.token;
        })
        .catch(e => {
          this.token = null;
          this.tokenExpires = null;
          const body = (e.response && e.response.data) ? e.response.data : {};
          let err = e;
          if (body.error) {
            const desc =
                body.error_description ? `: ${body.error_description}` : '';
            err = new Error(`${body.error}${desc}`);
          }
          throw err;
        });
  }
}
