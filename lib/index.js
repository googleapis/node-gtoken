var gp12pem = require('google-p12-pem');
var request = require('request');
var mime = require('mime');
var jws = require('jws');
var fs = require('fs');

var GOOGLE_TOKEN_URL = 'https://accounts.google.com/o/oauth2/token';

/**
 * Create a GoogleToken.
 *
 * @param {[type]}   options  Configuration object.
 */
function GoogleToken(options) {
  if (!(this instanceof GoogleToken)) {
    return new GoogleToken(options);
  }

  this._configure(options);
}

GoogleToken.prototype._configure = function(options) {
  var self = this;
  options = options || {};
  this.keyFile = options.keyFile;
  this.key = options.key;
  this.token = null;
  this.expires_at = null;
  this.raw_token = null;
  this.iat = null;

  /**
   * The email address of the service account.
   * @type {string}
   */
  this.iss = options.email || options.iss;

  /**
   * The email address of the user for which the application is
   * requesting delegated access.
   * @type {string}
   */
  if(options.sub) {
    this.sub = options.sub;
  }

  if (typeof options.scope === 'object') {
    this.scope = options.scope.join(' ');
  } else {
    this.scope = options.scope;
  }
};

GoogleToken.prototype.hasExpired = function() {
  var now = (new Date()).getTime();
  if (this.token && this.expires_at) {
    return now >= this.expires_at;
  } else {
    return true;
  }
};

GoogleToken.prototype.getToken = function(callback) {
  var self = this;

  if (!this.hasExpired()) {
    callback(null, this.token);
  } else {
    if (!this.key && !this.keyFile) {
      callback(new Error('No key or keyFile set.'));
      return;
    } else if (!this.key && this.keyFile) {
      var mimeType = mime.lookup(this.keyFile);
      if (mimeType === 'application/x-pkcs12') {
        // detect .p12 file and convert to .pem on the fly
        gp12pem(this.keyFile, handleKey);
      } else {
        // assume .pem key otherwise
        fs.readFile(this.keyFile, handleKey);
      }
    } else {
      this._requestToken(callback);
    }
  }

  function handleKey(err, key) {
    if (err) {
      callback(err);
      return;
    }
    self.key = key;
    self._requestToken(callback);
  }
};

GoogleToken.prototype._requestToken = function(callback) {
  var self = this;

  this._signJWT(function(err, signedJWT) {
    if (err) {
      callback(err, null);
      return;
    }
    self._makeRequest({
      url: GOOGLE_TOKEN_URL,
      form: {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: signedJWT
      }
    }, callback);
  });
};

GoogleToken.prototype._signJWT = function(callback) {
  var self = this;
  this.iat = Math.floor(new Date().getTime() / 1000);

  var payload = {
    iss: this.iss,
    scope: this.scope,
    aud: GOOGLE_TOKEN_URL,
    exp: this.iat + 3600, // 3600 seconds = 1 hour
    iat: this.iat
  };

  if (this.sub) {
    payload.sub = this.sub;
  }

  try {
    var signedJWT = jws.sign({
      header: {
        alg: 'RS256',
        typ: 'JWT'
      },
      payload: payload,
      secret: this.key
    });
    callback(null, signedJWT);
  } catch(err) {
    callback(err, null);
  }
};

GoogleToken.prototype._makeRequest = function(options, callback) {
  var self = this;
  request.post(options, function(err, res, body) {
    try {
      body = JSON.parse(body);
    } catch (e) {
      body = {};
    }

    err = err || body.error && new Error(body.error);

    if (err) {
      self.token = null;
      self.token_expires = null;
      callback(err, null);
      return;
    }

    self.raw_token = body;
    self.token = body.access_token;
    self.expires_at = (self.iat + body.expires_in) * 1000;
    callback(null, self.token);
  });
};

module.exports = GoogleToken;
