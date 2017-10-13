/**
* Module dependencies.
*/
var passport = require('passport'),
    jwt = require('jws')
    util = require('util');


/**
* `ClientJWTBearerStrategy` constructor.
*
* @api protected
*/
function Strategy(options, key, verify) {
  if (typeof options == 'function') {
    verify = key;
    key = options;
    options = undefined;
  }
  options = options || {};
  
  if (!verify) throw new Error('OAuth 2.0 JWT bearer strategy requires a verify function');

  passport.Strategy.call(this);
  this.name = 'oauth2-jwt-bearer';
  this._key = key;
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

  var type  = req.body['client_assertion_type'],
      assertion = req.body['client_assertion'],
      self = this;

  if (type != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
    return this.fail();
  }

  // Decode the JWT so the header and payload are available, as they contain
  // fields needed to find the corresponding key.  Note that at this point, the
  // assertion has not actually been verified.  It will be verified later, after
  // the keying material has been retrieved.
  var token = jwt.decode(assertion);
  if (!token) {
    return this.fail();
  }
  
  var header = token.header
    , payload = token.payload;

  // TODO: Check that we are the intended audience

  function doVerifyStep() {
    function verified(err, client, info) {
      if (err) { return self.error(err); }
      if (!client) { return self.fail(); }
      self.success(client, info);
    }
    
    // At this point, the assertion has been verified and authentication can
    // proceed.  Call the verify callback so the application can find and verify
    // the client instance.  Typically, the subject and issuer of the assertion
    // are the same, as the client is authenticating as itself.
    try {
      if (self._passReqToCallback) {
        var arity = self._key.length;
        if (arity == 4) {
          // This variation allows the application to detect the case in which
          // the issuer and subject of the assertion are different, and permit
          // or deny as necessary.
          self._verify(req, payload.iss || header.iss, header, verified);
        } else { // arity == 3
          self._verify(req, payload.iss || header.iss, keyed);
        }
      } else {
        var arity = self._key.length;
        if (arity == 3) {
          // This variation allows the application to detect the case in which
          // the issuer and subject of the assertion are different, and permit
          // or deny as necessary.
          self._verify(payload.sub || payload.iss, payload.iss, verified);
        } else { // arity == 2
          self._verify(payload.sub || payload.iss, verified);
        }
      }
    } catch (ex) {
      return self.error(ex);
    }
  }

  function doKeyStep() {
    function keyed(err, key) {
      if (err) { return self.error(err); }
      if (!key) { return self.fail(); }
      
      // The key has been retrieved, verify the assertion.  `key` is a PEM
      // encoded RSA public key, DSA public key, or X.509 certificate, as
      // supported by Node's `crypto` module.
      var ok = jwt.verify(assertion, key);
      if (!ok) { return self.fail(); }
      doVerifyStep();
    }
    
    try {
      if (self._passReqToCallback) {
        var arity = self._key.length;
        if (arity == 4) {
          self._key(req, payload.iss || header.iss, header, keyed);
        } else { // arity == 3
          self._key(req, payload.iss || header.iss, keyed);
        }
      } else {
        var arity = self._key.length;
        if (arity == 3) {
          self._key(payload.iss || header.iss, header, keyed);
        } else { // arity == 2
          self._key(payload.iss || header.iss, keyed);
        }
      }
    } catch (ex) {
      return self.error(ex);
    }
  }

  doKeyStep();
};


/**
* Expose `Strategy`.
*/
module.exports = Strategy;
