/**
 * Copyright 2018 Google LLC
 *
 * Distributed under MIT license.
 * See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as nock from 'nock';
import {GoogleToken} from '../src';

const EMAIL = 'example@developer.gserviceaccount.com';
const UNKNOWN_KEYFILE = './test/assets/key';
const KEYFILE = './test/assets/key.pem';
const P12FILE = './test/assets/key.p12';
const KEYFILEJSON = './test/assets/key.json';
const KEYFILENOEMAILJSON = './test/assets/key-no-email.json';
const KEYCONTENTS = fs.readFileSync(KEYFILE, 'utf8');
const KEYJSONCONTENTS = fs.readFileSync(KEYFILEJSON, 'utf8');
const GOOGLE_TOKEN_URLS = ['https://www.googleapis.com', '/oauth2/v4/token'];
const GOOGLE_REVOKE_TOKEN_URLS = [
  'https://accounts.google.com',
  '/o/oauth2/revoke',
  '?token=',
];

const TESTDATA = {
  email: 'email@developer.gserviceaccount.com',
  scope: 'scope123', // or space-delimited string of scopes
  key: KEYCONTENTS,
};

const TESTDATA_KEYFILE = {
  email: 'email@developer.gserviceaccount.com',
  sub: 'developer@gmail.com',
  scope: 'scope123', // or space-delimited string of scopes
  keyFile: KEYFILE,
};

const TESTDATA_UNKNOWN = {
  keyFile: UNKNOWN_KEYFILE,
};

const TESTDATA_KEYFILENOEMAIL = {
  scope: 'scope123', // or space-delimited string of scopes
  keyFile: KEYFILE,
};

const TESTDATA_KEYFILEJSON = {
  scope: 'scope123', // or space-delimited string of scopes
  keyFile: KEYFILEJSON,
};

const TESTDATA_KEYFILENOEMAILJSON = {
  scope: 'scope123', // or space-delimited string of scopes
  keyFile: KEYFILENOEMAILJSON,
};

const TESTDATA_P12 = {
  email: 'email@developer.gserviceaccount.com',
  scope: 'scope123', // or space-delimited string of scopes
  keyFile: P12FILE,
};

const TESTDATA_P12_NO_EMAIL = {
  scope: 'scope123', // or space-delimited string of scopes
  keyFile: P12FILE,
};

nock.disableNetConnect();

it('should exist', () => {
  assert.strictEqual(typeof GoogleToken, 'function');
});

it('should work without new or options', () => {
  const gtoken = new GoogleToken();
  assert(gtoken);
});

describe('.iss', () => {
  it('should be set from email option', () => {
    const gtoken = new GoogleToken({email: EMAIL});
    assert.strictEqual(gtoken.iss, EMAIL);
    assert.strictEqual(gtoken.email, undefined);
  });

  it('should be set from iss option', () => {
    const gtoken = new GoogleToken({iss: EMAIL});
    assert.strictEqual(gtoken.iss, EMAIL);
  });

  it('should be set from sub option', () => {
    const gtoken = new GoogleToken({sub: EMAIL});
    assert.strictEqual(gtoken.sub, EMAIL);
  });

  it('should be set from email option over iss option', () => {
    const gtoken = new GoogleToken({iss: EMAIL, email: 'another' + EMAIL});
    assert.strictEqual(gtoken.iss, 'another' + EMAIL);
  });
});

describe('.scope', () => {
  it('should accept strings', () => {
    const gtoken = new GoogleToken({scope: 'hello world'});
    assert.strictEqual(gtoken.scope, 'hello world');
  });

  it('should accept array of strings', () => {
    const gtoken = new GoogleToken({scope: ['hello', 'world']});
    assert.strictEqual(gtoken.scope, 'hello world');
  });
});

describe('.hasExpired()', () => {
  it('should exist', () => {
    const gtoken = new GoogleToken();
    assert.strictEqual(typeof gtoken.hasExpired, 'function');
  });

  it('should detect expired tokens', () => {
    const gtoken = new GoogleToken();
    assert(gtoken.hasExpired(), 'should be expired without token');
    gtoken.rawToken = {
      access_token: 'hello',
    };
    assert(gtoken.hasExpired(), 'should be expired without expires_at');
    gtoken.expiresAt = new Date().getTime() + 10000;
    assert(!gtoken.hasExpired(), 'shouldnt be expired with future date');
    gtoken.expiresAt = new Date().getTime() - 10000;
    assert(gtoken.hasExpired(), 'should be expired with past date');
    gtoken.expiresAt = new Date().getTime() + 10000;
    gtoken.rawToken = undefined;
    assert(gtoken.hasExpired(), 'should be expired with no token');
  });
});

describe('.revokeToken()', () => {
  it('should exist', () => {
    const gtoken = new GoogleToken();
    assert.strictEqual(typeof gtoken.revokeToken, 'function');
  });

  it('should run accept config properties', done => {
    const token = 'w00t';
    const scope = createRevokeMock(token);
    const gtoken = new GoogleToken();
    gtoken.rawToken = {
      access_token: token,
    };
    gtoken.revokeToken(err => {
      assert.strictEqual(gtoken.accessToken, undefined);
      scope.done();
      done();
    });
  });

  it('should return appropriate error with HTTP 404s', done => {
    const token = 'w00t';
    const scope = createRevokeMock(token, 404);
    const gtoken = new GoogleToken();
    gtoken.rawToken = {
      access_token: token,
    };
    gtoken.revokeToken(err => {
      assert(err);
      scope.done();
      done();
    });
  });

  it('should run accept config properties with async', async () => {
    const token = 'w00t';
    const scope = createRevokeMock(token);
    const gtoken = new GoogleToken();
    gtoken.rawToken = {
      access_token: token,
    };
    await gtoken.revokeToken();
    assert.strictEqual(gtoken.accessToken, undefined);
    scope.done();
  });

  it('should return error when no token set', done => {
    const gtoken = new GoogleToken();
    gtoken.rawToken = {
      access_token: undefined,
    };
    gtoken.revokeToken(err => {
      assert(err && err.message);
      done();
    });
  });

  it('should return error when no token set with async', async () => {
    const gtoken = new GoogleToken();
    gtoken.rawToken = {
      access_token: undefined,
    };
    let err;
    try {
      await gtoken.revokeToken();
    } catch (e) {
      err = e;
    }
    assert(err && err.message);
  });
});

describe('.getToken()', () => {
  it('should exist', () => {
    const gtoken = new GoogleToken();
    assert.strictEqual(typeof gtoken.getToken, 'function');
  });

  it('should read .pem keyFile from file', done => {
    const gtoken = new GoogleToken(TESTDATA_KEYFILE);
    const scope = createGetTokenMock();
    gtoken.getToken((err, token) => {
      assert.deepStrictEqual(gtoken.key, KEYCONTENTS);
      scope.done();
      done();
    });
  });

  it('should read .pem keyFile from file async', async () => {
    const gtoken = new GoogleToken(TESTDATA_KEYFILE);
    const scope = createGetTokenMock();
    const token = await gtoken.getToken();
    scope.done();
    assert.deepStrictEqual(gtoken.key, KEYCONTENTS);
  });

  it('should return error if iss is not set with .pem', done => {
    const gtoken = new GoogleToken(TESTDATA_KEYFILENOEMAIL);
    gtoken.getToken(err => {
      assert(err);
      if (err) {
        assert.strictEqual(
          (err as NodeJS.ErrnoException).code,
          'MISSING_CREDENTIALS'
        );
        done();
      }
    });
  });

  it('should return err if neither key nor keyfile are set', done => {
    const gtoken = new GoogleToken();
    gtoken.getToken((err, token) => {
      assert(err);
      done();
    });
  });

  it('should read .json key from file', done => {
    const gtoken = new GoogleToken(TESTDATA_KEYFILEJSON);
    const scope = createGetTokenMock();
    gtoken.getToken((err, token) => {
      scope.done();
      assert.strictEqual(err, null);
      const parsed = JSON.parse(KEYJSONCONTENTS);
      assert.deepStrictEqual(gtoken.key, parsed.private_key);
      assert.deepStrictEqual(gtoken.iss, parsed.client_email);
      done();
    });
  });

  it('should accept additional claims', async () => {
    const opts = Object.assign(TESTDATA_KEYFILE, {
      additionalClaims: {fancyClaim: 'isFancy'},
    });
    const gtoken = new GoogleToken(opts);
    const scope = createGetTokenMock();
    const token = await gtoken.getToken();
    scope.done();
    assert.deepStrictEqual(gtoken.key, KEYCONTENTS);
  });

  it('should return error if iss is not set with .json', done => {
    const gtoken = new GoogleToken(TESTDATA_KEYFILENOEMAILJSON);
    gtoken.getToken(err => {
      assert(err);
      if (err) {
        assert.strictEqual(
          (err as NodeJS.ErrnoException).code,
          'MISSING_CREDENTIALS'
        );
        done();
      }
    });
  });

  it('should return cached token if not expired', done => {
    const gtoken = new GoogleToken(TESTDATA);
    gtoken.rawToken = {
      access_token: 'mytoken',
    };
    gtoken.expiresAt = new Date().getTime() + 10000;
    gtoken.getToken((err, token) => {
      assert.strictEqual(token!.access_token, 'mytoken');
      done();
    });
  });

  it('should not use cached token if forceRefresh=true (promise)', async () => {
    const gtoken = new GoogleToken(TESTDATA);
    gtoken.rawToken = {
      access_token: 'mytoken',
    };
    gtoken.expiresAt = new Date().getTime() + 10000;
    const fakeToken = 'abc123';
    const scope = createGetTokenMock(200, {access_token: fakeToken});
    const token = await gtoken.getToken({forceRefresh: true});
    assert.strictEqual(token.access_token, fakeToken);
  });

  it('should not use cached token if forceRefresh=true (cb)', done => {
    const gtoken = new GoogleToken(TESTDATA);
    gtoken.rawToken = {
      access_token: 'mytoken',
    };
    gtoken.expiresAt = new Date().getTime() + 10000;
    const fakeToken = 'qwerty';
    const scope = createGetTokenMock(200, {access_token: fakeToken});
    gtoken.getToken(
      (err, token) => {
        assert.ifError(err);
        assert.strictEqual(token!.access_token, fakeToken);
        done();
      },
      {forceRefresh: true}
    );
  });

  it('should run gp12pem if .p12 file is given', done => {
    const gtoken = new GoogleToken(TESTDATA_P12);
    const scope = createGetTokenMock();
    gtoken.getToken((err, token) => {
      scope.done();
      assert.strictEqual(err, null);
      done();
    });
  });

  it('should return error if iss is not set with .p12', done => {
    const gtoken = new GoogleToken(TESTDATA_P12_NO_EMAIL);
    gtoken.getToken(err => {
      assert(err);
      if (err) {
        assert.strictEqual(
          (err as NodeJS.ErrnoException).code,
          'MISSING_CREDENTIALS'
        );
        done();
      }
    });
  });

  it('should return error if unknown file type is used', done => {
    const gtoken = new GoogleToken(TESTDATA_UNKNOWN);
    gtoken.getToken(err => {
      assert(err);
      if (err) {
        assert.strictEqual(
          (err as NodeJS.ErrnoException).code,
          'UNKNOWN_CERTIFICATE_TYPE'
        );
        done();
      }
    });
  });

  it('should expose token response as getters', async () => {
    const idToken = '🧼';
    const tokenType = '😳';
    const refreshToken = '🤮';
    const gtoken = new GoogleToken(TESTDATA_KEYFILEJSON);
    gtoken.rawToken = {};
    assert.strictEqual(gtoken.idToken, undefined);
    assert.strictEqual(gtoken.tokenType, undefined);
    assert.strictEqual(gtoken.refreshToken, undefined);
    gtoken.rawToken = {
      id_token: idToken,
      token_type: tokenType,
      refresh_token: refreshToken,
    };
    assert.strictEqual(idToken, gtoken.idToken);
    assert.strictEqual(tokenType, gtoken.tokenType);
    assert.strictEqual(refreshToken, gtoken.refreshToken);
  });

  describe('request', () => {
    it('should be run with correct options', done => {
      const gtoken = new GoogleToken(TESTDATA);
      const fakeToken = 'nodeftw';
      const scope = createGetTokenMock(200, {access_token: fakeToken});
      gtoken.getToken((err, token) => {
        scope.done();
        assert.strictEqual(err, null);
        assert.strictEqual(token!.access_token, fakeToken);
        done();
      });
    });

    it('should set and return correct properties on success', done => {
      const gtoken = new GoogleToken(TESTDATA);
      const RESPBODY = {
        access_token: 'accesstoken123',
        expires_in: 3600,
        token_type: 'Bearer',
      };
      const scope = createGetTokenMock(200, RESPBODY);
      gtoken.getToken((err, token) => {
        scope.done();
        assert.deepStrictEqual(gtoken.rawToken, RESPBODY);
        assert.strictEqual(gtoken.accessToken, 'accesstoken123');
        assert.deepStrictEqual(gtoken.rawToken, token);
        assert.strictEqual(err, null);
        assert(gtoken.expiresAt);
        if (gtoken.expiresAt) {
          assert(gtoken.expiresAt >= new Date().getTime());
          assert(gtoken.expiresAt <= new Date().getTime() + 3600 * 1000);
        }
        done();
      });
    });

    it('should set and return correct properties on error', done => {
      const ERROR = 'An error occurred.';
      const gtoken = new GoogleToken(TESTDATA);
      const scope = createGetTokenMock(500, {error: ERROR});
      gtoken.getToken((err, token) => {
        scope.done();
        assert(err);
        assert.strictEqual(gtoken.rawToken, undefined);
        assert.strictEqual(gtoken.accessToken, undefined);
        if (err) assert.strictEqual(err.message, ERROR);
        assert.strictEqual(gtoken.expiresAt, undefined);
        done();
      });
    });

    it('should include error_description from remote error', done => {
      const gtoken = new GoogleToken(TESTDATA);
      const ERROR = 'error_name';
      const DESCRIPTION = 'more detailed message';
      const RESPBODY = {error: ERROR, error_description: DESCRIPTION};
      const scope = createGetTokenMock(500, RESPBODY);
      gtoken.getToken((err, token) => {
        scope.done();
        assert(err instanceof Error);
        if (err) {
          assert.strictEqual(err.message, ERROR + ': ' + DESCRIPTION);
          done();
        }
      });
    });

    it('should provide an appropriate error for a 404', done => {
      const gtoken = new GoogleToken(TESTDATA);
      const message = 'Request failed with status code 404';
      const scope = createGetTokenMock(404);
      gtoken.getToken((err, token) => {
        scope.done();
        assert(err instanceof Error);
        if (err) assert.strictEqual(err.message, message);
        done();
      });
    });
  });

  it('should return credentials outside of getToken flow', async () => {
    const gtoken = new GoogleToken(TESTDATA_KEYFILEJSON);
    const creds = await gtoken.getCredentials(KEYFILEJSON);
    assert(creds.privateKey);
    assert(creds.clientEmail);
  });

  // see: https://github.com/googleapis/google-api-nodejs-client/issues/1614
  it('should throw exception if readFile not available, and keyFile provided', async () => {
    // Fake an environment in which fs.readFile does not
    // exist. This is the same as when running in the browser.
    delete require.cache[require.resolve('../src')];
    delete require.cache[require.resolve('fs')];
    const fs = require('fs');
    delete fs.readFile;
    const {GoogleToken} = require('../src');

    let message;
    try {
      const gtoken = new GoogleToken(TESTDATA_KEYFILEJSON);
      await gtoken.getCredentials(KEYFILEJSON);
    } catch (err) {
      message = err.message;
    }
    assert.strictEqual(message, 'use key rather than keyFile.');
  });
});

function createGetTokenMock(code = 200, body?: {}) {
  return nock(GOOGLE_TOKEN_URLS[0])
    .replyContentLength()
    .post(
      GOOGLE_TOKEN_URLS[1],
      {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: /.?/,
      },
      {reqheaders: {'Content-Type': 'application/x-www-form-urlencoded'}}
    )
    .reply(code, body);
}

function createRevokeMock(token: string, code = 200) {
  return nock(GOOGLE_REVOKE_TOKEN_URLS[0])
    .get(GOOGLE_REVOKE_TOKEN_URLS[1])
    .query({token})
    .reply(code);
}
