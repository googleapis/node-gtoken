import * as fs from 'fs';
import * as mime from 'mime';
import * as request from 'request';

const gp12pem = require('google-p12-pem');
const jws = require('jws');

const GOOGLE_TOKEN_URL = 'https://accounts.google.com/o/oauth2/token';
const GOOGLE_REVOKE_TOKEN_URL =
    'https://accounts.google.com/o/oauth2/revoke?token=';

interface Payload {
  iss: string;
  scope: string|Array<string>;
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
  scope?: string|Array<string>;
}

export class GoogleToken {
  public token: string|null;
  public expiresAt: number|null;
  public key: string|undefined;
  public keyFile: string|undefined;
  public iss: string|undefined;
  public sub: string;
  public scope: string|undefined;
  public rawToken: string|null;
  public tokenExpires: number|null;
  public email: string;

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
  public hasExpired() {
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
  public getToken(callback: (err: Error|null, token?: string|null) => void):
      void {
    const handleJSONKey = (err: Error, key: string) => {
      if (err) {
        callback(err);
        return;
      }
      try {
        const body = JSON.parse(key);
        this.key = body.private_key;
        this.iss = body.client_email;
      } catch (e) {
        callback(e);
        return;
      }

      if (!this.key || !this.iss) {
        const error = new Error('private_key and client_email are required.');
        (error as NodeJS.ErrnoException).code = 'MISSING_CREDENTIALS';
        callback(error);
        return;
      }

      this.requestToken(callback);
    };

    const handleKey = (err: Error, key: string) => {
      if (err) {
        callback(err);
        return;
      }
      this.key = key;
      this.requestToken(callback);
    };

    if (!this.hasExpired()) {
      setImmediate(callback, null, this.token);
      return;
    } else {
      if (!this.key && !this.keyFile) {
        setImmediate(callback, new Error('No key or keyFile set.'));
        return;
      } else if (!this.key && this.keyFile) {
        const mimeType = mime.getType(this.keyFile);
        if (mimeType === 'application/json') {
          // json file
          fs.readFile(this.keyFile, 'utf8', handleJSONKey);
        } else {
          // Must be a .p12 file or .pem key
          if (!this.iss) {
            const error = new Error('email is required.');
            (error as NodeJS.ErrnoException).code = 'MISSING_CREDENTIALS';
            setImmediate(callback, error);
            return;
          }

          if (mimeType === 'application/x-pkcs12') {
            // convert to .pem on the fly
            gp12pem(this.keyFile, handleKey);
          } else {
            // assume .pem key otherwise
            fs.readFile(this.keyFile, 'utf8', handleKey);
          }
        }
      } else {
        return this.requestToken(callback);
      }
    }
  }

  /**
   * Revoke the token if one is set.
   *
   * @param callback The callback function.
   */
  public revokeToken(callback: (err?: Error) => void): void {
    if (this.token) {
      request(GOOGLE_REVOKE_TOKEN_URL + this.token, (err: Error) => {
        if (err) {
          callback(err);
          return;
        }
        this.configure({
          email: this.iss,
          sub: this.sub,
          key: this.key,
          keyFile: this.keyFile,
          scope: this.scope
        });
        callback();
      });
    } else {
      setImmediate(callback, new Error('No token to revoke.'));
    }
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
  private requestToken(callback: (err: Error|null, token: string|null) => void):
      void {
    const iat = Math.floor(new Date().getTime() / 1000);
    const payload = <Payload>{
      iss: this.iss,
      scope: this.scope,
      aud: GOOGLE_TOKEN_URL,
      exp: iat + 3600,  // 3600 seconds = 1 hour
      iat: iat,
    };

    if (this.sub) {
      payload.sub = this.sub;
    }

    const toSign = {
      header: {alg: 'RS256', typ: 'JWT'},
      payload: payload,
      secret: this.key
    };

    let signedJWT: string;
    try {
      signedJWT = jws.sign(toSign);
    } catch (e) {
      setImmediate(callback, e, null);
      return;
    }

    request(
        {
          method: 'post',
          url: GOOGLE_TOKEN_URL,
          form: {
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion: signedJWT
          }
        },
        (err2: Error, res: request.RequestResponse, body: any) => {
          try {
            body = JSON.parse(body);
          } catch (e) {
            body = {};
          }

          err2 = err2 ||
              body.error &&
                  new Error(
                      body.error +
                      (body.error_description ? ': ' + body.error_description :
                                                ''));

          if (err2) {
            this.token = null;
            this.tokenExpires = null;
            callback(err2, null);
            return;
          }

          this.rawToken = body;
          this.token = body.access_token;
          this.expiresAt = (iat + body.expires_in) * 1000;
          return callback(null, this.token);
        });
    return;
  }
}
