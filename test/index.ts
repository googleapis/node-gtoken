import * as assert from 'assert';
import * as fs from 'fs';
import * as mime from 'mime';
import * as nock from 'nock';
import * as request from 'request';

import {GoogleToken} from '../src/lib/index';

const EMAIL = 'example@developer.gserviceaccount.com';
const KEYFILE = './test/assets/key.pem';
const P12FILE = './test/assets/key.p12';
const KEYFILEJSON = './test/assets/key.json';
const KEYFILENOEMAILJSON = './test/assets/key-no-email.json';
const KEYCONTENTS = fs.readFileSync(KEYFILE, 'utf8');
const KEYJSONCONTENTS = fs.readFileSync(KEYFILEJSON, 'utf8');
const SCOPE1 = 'https://www.googleapis.com/auth/urlshortener';
const SCOPE2 = 'https://www.googleapis.com/auth/drive';
const SCOPES = [SCOPE1, SCOPE2];

const GOOGLE_TOKEN_URLS = ['https://accounts.google.com', '/o/oauth2/token'];
const GOOGLE_REVOKE_TOKEN_URLS =
    ['https://accounts.google.com', '/o/oauth2/revoke', '?token='];

const TESTDATA = {
  email: 'email@developer.gserviceaccount.com',
  scope: 'scope123',  // or space-delimited string of scopes
  key: KEYCONTENTS
};

const TESTDATA_KEYFILE = {
  email: 'email@developer.gserviceaccount.com',
  scope: 'scope123',  // or space-delimited string of scopes
  keyFile: KEYFILE
};

const TESTDATA_KEYFILENOEMAIL = {
  scope: 'scope123',  // or space-delimited string of scopes
  keyFile: KEYFILE
};

const TESTDATA_KEYFILEJSON = {
  scope: 'scope123',  // or space-delimited string of scopes
  keyFile: KEYFILEJSON
};

const TESTDATA_KEYFILENOEMAILJSON = {
  scope: 'scope123',  // or space-delimited string of scopes
  keyFile: KEYFILENOEMAILJSON
};

const TESTDATA_P12 = {
  email: 'email@developer.gserviceaccount.com',
  scope: 'scope123',  // or space-delimited string of scopes
  keyFile: P12FILE
};

const TESTDATA_P12_NO_EMAIL = {
  scope: 'scope123',  // or space-delimited string of scopes
  keyFile: P12FILE
};

const MIME = {
  getType: (filename: string) => {
    if (filename === P12FILE) {
      return 'application/x-pkcs12';
    } else if (filename === KEYFILEJSON) {
      return 'application/json';
    } else {
      return '';
    }
  },
  getExtension: (filename: string) => {
    return null;
  },
  define: (mimes: mime.TypeMap, force?: boolean) => null,
  default_type: 'null'
};

const noop = () => undefined;

describe('gtoken', () => {
  it('should exist', () => {
    assert.equal(typeof GoogleToken, 'function');
  });

  it('should work without new or options', () => {
    const gtoken = new GoogleToken();
    assert(gtoken);
  });

  describe('.iss', () => {
    it('should be set from email option', () => {
      const gtoken = new GoogleToken({email: EMAIL});
      assert.equal(gtoken.iss, EMAIL);
      assert.equal(gtoken.email, undefined);
    });

    it('should be set from iss option', () => {
      const gtoken = new GoogleToken({iss: EMAIL});
      assert.equal(gtoken.iss, EMAIL);
    });

    it('should be set from email option over iss option', () => {
      const gtoken = new GoogleToken({iss: EMAIL, email: 'another' + EMAIL});
      assert.equal(gtoken.iss, 'another' + EMAIL);
    });
  });

  describe('.scope', () => {
    it('should accept strings', () => {
      const gtoken = new GoogleToken({scope: 'hello world'});
      assert.equal(gtoken.scope, 'hello world');
    });

    it('should accept array of strings', () => {
      const gtoken = new GoogleToken({scope: ['hello', 'world']});
      assert.equal(gtoken.scope, 'hello world');
    });
  });

  describe('.hasExpired()', () => {
    it('should exist', () => {
      const gtoken = new GoogleToken();
      assert.equal(typeof gtoken.hasExpired, 'function');
    });

    it('should detect expired tokens', () => {
      const gtoken = new GoogleToken();
      assert(gtoken.hasExpired(), 'should be expired without token');
      gtoken.token = 'hello';
      assert(gtoken.hasExpired(), 'should be expired without expires_at');
      gtoken.expiresAt = (new Date().getTime()) + 10000;
      assert(!gtoken.hasExpired(), 'shouldnt be expired with future date');
      gtoken.expiresAt = (new Date().getTime()) - 10000;
      assert(gtoken.hasExpired(), 'should be expired with past date');
      gtoken.expiresAt = (new Date().getTime()) + 10000;
      gtoken.token = null;
      assert(gtoken.hasExpired(), 'should be expired with no token');
    });
  });

  describe('.revokeToken()', () => {
    it('should exist', () => {
      const gtoken = new GoogleToken();
      assert.equal(typeof gtoken.revokeToken, 'function');
    });


    it('should run accept config properties', done => {
      const token = 'w00t';

      nock(GOOGLE_REVOKE_TOKEN_URLS[0])
          .get(GOOGLE_REVOKE_TOKEN_URLS[1])
          .query({token: token})
          .reply(200);

      const gtoken = new GoogleToken();
      gtoken.token = token;
      gtoken.revokeToken(err => {
        assert.equal(gtoken.token, null);
        done();
      });
    });

    it('should return error when no token set', done => {
      const gtoken = new GoogleToken();
      gtoken.token = null;
      gtoken.revokeToken(err => {
        assert(err && err.message);
        done();
      });
    });
  });

  describe('.getToken()', () => {
    it('should exist', () => {
      const gtoken = new GoogleToken();
      assert.equal(typeof gtoken.getToken, 'function');
    });

    it('should read .pem keyFile from file', done => {
      const gtoken = new GoogleToken(TESTDATA_KEYFILE);
      createMock();
      gtoken.getToken((err, token) => {
        assert.deepEqual(gtoken.key, KEYCONTENTS);
        done();
      });
    });

    it('should return error if iss is not set with .pem', done => {
      const gtoken = new GoogleToken(TESTDATA_KEYFILENOEMAIL);
      gtoken.getToken(err => {
        assert(err);
        if (err) {
          assert.strictEqual(
              (<NodeJS.ErrnoException>err).code, 'MISSING_CREDENTIALS');
          done();
        }
      });
    });

    it('should read .json key from file', done => {
      const gtoken = new GoogleToken(TESTDATA_KEYFILEJSON);
      createMock();
      gtoken.getToken((err, token) => {
        assert.equal(err, null);
        const parsed = JSON.parse(KEYJSONCONTENTS);
        assert.deepEqual(gtoken.key, parsed.private_key);
        assert.deepEqual(gtoken.iss, parsed.client_email);
        done();
      });
    });

    it('should return error if iss is not set with .json', done => {
      const gtoken = new GoogleToken(TESTDATA_KEYFILENOEMAILJSON);
      gtoken.getToken(err => {
        assert(err);
        if (err) {
          assert.strictEqual(
              (<NodeJS.ErrnoException>err).code, 'MISSING_CREDENTIALS');
          done();
        }
      });
    });

    it('should return cached token if not expired', done => {
      const gtoken = new GoogleToken(TESTDATA);
      gtoken.token = 'mytoken';
      gtoken.expiresAt = new Date().getTime() + 10000;
      gtoken.getToken((err, token) => {
        assert.equal(token, 'mytoken');
        done();
      });
    });

    it('should run gp12pem if .p12 file is given', done => {
      const gtoken = new GoogleToken(TESTDATA_P12);
      createMock();
      gtoken.getToken((err, token) => {
        assert.equal(err, null);
        done();
      });
    });

    it('should return error if iss is not set with .p12', done => {
      const gtoken = new GoogleToken(TESTDATA_P12_NO_EMAIL);
      gtoken.getToken(err => {
        assert(err);
        if (err) {
          assert.strictEqual(
              (<NodeJS.ErrnoException>err).code, 'MISSING_CREDENTIALS');
          done();
        }
      });
    });

    describe('request', () => {
      it('should be run with correct options', done => {
        const gtoken = new GoogleToken(TESTDATA);
        const fakeToken = 'nodeftw';
        createMock(200, {'access_token': fakeToken});
        gtoken.getToken((err, token) => {
          assert.equal(err, null);
          assert.equal(token, fakeToken);
          done();
        });
      });

      it('should set and return correct properties on success', done => {
        const gtoken = new GoogleToken(TESTDATA);

        const RESPBODY = {
          access_token: 'accesstoken123',
          expires_in: 3600,
          token_type: 'Bearer'
        };
        createMock(200, RESPBODY);
        gtoken.getToken((err, token) => {
          assert.deepEqual(gtoken.rawToken, RESPBODY);
          assert.equal(gtoken.token, 'accesstoken123');
          assert.equal(gtoken.token, token);
          assert.equal(err, null);
          assert(gtoken.expiresAt);
          if (gtoken.expiresAt) {
            assert(gtoken.expiresAt >= (new Date()).getTime());
            assert(gtoken.expiresAt <= (new Date()).getTime() + (3600 * 1000));
          }
          done();
        });
      });

      it('should set and return correct properties on error', done => {
        const ERROR = 'An error occurred.';
        const gtoken = new GoogleToken(TESTDATA);

        createMock(500, {error: ERROR});

        gtoken.getToken((err, token) => {
          assert(err);
          assert.equal(gtoken.rawToken, null);
          assert.equal(gtoken.token, null);
          assert.equal(gtoken.token, token);
          if (err) assert.equal(err.message, ERROR);
          assert.equal(gtoken.expiresAt, null);
          done();
        });
      });

      it('should include error_description from remote error', done => {
        const gtoken = new GoogleToken(TESTDATA);
        const ERROR = 'error_name';
        const DESCRIPTION = 'more detailed message';
        const RESPBODY = {error: ERROR, error_description: DESCRIPTION};

        createMock(500, RESPBODY);

        gtoken.getToken((err, token) => {
          assert(err instanceof Error);
          if (err) {
            assert.equal(err.message, ERROR + ': ' + DESCRIPTION);
            done();
          }
        });
      });
    });
  });
});

function createMock(code = 200, body?: any) {
  nock(GOOGLE_TOKEN_URLS[0])
      .post(GOOGLE_TOKEN_URLS[1], {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: /.?/
      })
      .reply(code, body);
}
