var assert = require('assert');
var GoogleToken = require('../lib/index.js');
var EMAIL = 'example@developer.gserviceaccount.com';
var KEYFILE = './test/assets/key.pem';
var SCOPE1 = 'https://www.googleapis.com/auth/urlshortener';
var SCOPE2 = 'https://www.googleapis.com/auth/drive';
var SCOPES = [ SCOPE1, SCOPE2 ];

describe('gtoken', function() {
  it('should exist', function() {
    assert.equal(typeof GoogleToken, 'function');
  });

  it('should work without new or options', function() {
    var gtoken = require('../lib/index.js')();
    assert(gtoken);
  });

  describe('.iss', function() {
    it('should be set from email option', function() {
      var gtoken = require('../lib/index.js')({
        email: EMAIL
      });
      assert.equal(gtoken.iss, EMAIL);
      assert.equal(gtoken.email, undefined);
    });

    it('should be set from iss option', function() {
      var gtoken = require('../lib/index.js')({
        iss: EMAIL
      });
      assert.equal(gtoken.iss, EMAIL);
    });

    it('should be set from email option over iss option', function() {
      var gtoken = require('../lib/index.js')({
        iss: EMAIL,
        email: 'another' + EMAIL
      });
      assert.equal(gtoken.iss, 'another' + EMAIL);
    });
  });

  describe('.scope', function() {
    it('should accept strings', function() {
      var gtoken = require('../lib/index.js')({
        scope: 'hello world'
      });
      assert.equal(gtoken.scope, 'hello world');
    });

    it('should accept array of strings', function() {
      var gtoken = require('../lib/index.js')({
        scope: [ 'hello', 'world' ]
      });
      assert.equal(gtoken.scope, 'hello world');
    });
  });

  describe('.hasExpired()', function() {
    it('should exist', function() {
      var gtoken = require('../lib/index.js')();
      assert.equal(typeof gtoken.hasExpired, 'function');
    });

    it('should detect expired tokens', function() {
      var gtoken = require('../lib/index.js')();
      assert(gtoken.hasExpired(), 'should be expired without token');
      gtoken.token = 'hello';
      assert(gtoken.hasExpired(), 'should be expired without expires_at');
      gtoken.expires_at = (new Date().getTime()) + 10000;
      assert(!gtoken.hasExpired(), 'shouldnt be expired with future date');
      gtoken.expires_at = (new Date().getTime()) - 10000;
      assert(gtoken.hasExpired(), 'should be expired with past date');
      gtoken.expires_at = (new Date().getTime()) + 10000;
      gtoken.token = null;
      assert(gtoken.hasExpired(), 'should be expired with no token');
    });
  });

  describe('.getToken()', function() {
    it('should exist', function() {
      var gtoken = require('../lib/index.js')();
      assert.equal(typeof gtoken.getToken, 'function');
    });
  });
});


