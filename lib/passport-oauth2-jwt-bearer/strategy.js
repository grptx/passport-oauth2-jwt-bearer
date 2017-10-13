/**
* Module dependencies.
*/
var passport = require('passport'),
    util = require('util');


/**
* `ClientJWTBearerStrategy` constructor.
*
* @api protected
*/
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('OAuth 2.0 JWT bearer strategy requires a verify function');

  passport.Strategy.call(this);
  this.name = 'oauth2-jwt-bearer';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
* Inherit from `passport.Strategy`.
*/
util.inherits(Strategy, passport.Strategy);

/**
* Authenticate request based on client credentials from the claimSet.iss of the JWT in the request body.
*
* @param {Object} req
* @api protected
*/
Strategy.prototype.authenticate = function(req) {
  if (!req.body || (!req.body['client_assertion_type'] || !req.body['client_assertion'])) {
    return this.fail();
  }

  var contents = [],
      type  = req.body['client_assertion_type']
      jwtBearer = req.body['client_assertion'],
      separator = '.',
      self = this;

  if (type != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
    return this.fail();
  }

  contents = jwtBearer.split(separator);

  if (!Array.isArray(contents)) { contents = [ contents ]; }

  if (contents.length != 3) {
    return this.fail();
  }

  function verified(err, client, info) {
    if (err) { return self.error(err); }
    if (!client) { return self.fail(); }
    self.success(client, info);
  }

  function base64urlDecode(str) {
    return new Buffer(base64urlUnescape(str), 'base64').toString();
  }

  function base64urlUnescape(str) {
    str += Array(5 - str.length % 4).join('=');
    return str.replace(/\-/g, '+').replace(/_/g, '/');
  }

  // contents[0] = header, contents[1] = claimSet, contents[2] = signature
  var claimSet = JSON.parse(base64urlDecode(contents[1]));

  if (!claimSet || !claimSet.iss) {
    return this.fail();
  }

  if (self._passReqToCallback) {
    this._verify(req, claimSet.iss, verified);
  } else {
    this._verify(claimSet.iss, verified);
  }
};


/**
* Expose `Strategy`.
*/
module.exports = Strategy;
