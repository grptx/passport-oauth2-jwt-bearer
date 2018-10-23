'use strict';

const passport = require('passport');
const jwt = require('jws');
const util = require('util');

/**
 * @constructor
 * @protected
 */
function Strategy(options, key, verify) {
  if (typeof options === 'function') {
    verify = key;
    key = options;
    options = undefined;
  }
  options = options || {};
  if (!verify) {
    throw new Error('OAuth 2.0 JWT bearer strategy requires a verify function');
  }
  //noinspection JSUnresolvedFunction
  passport.Strategy.call(this);
  this.name = 'oauth2-jwt-bearer';
  this._key = key;
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on client credentials from the claimSet.iss
 * of the JWT in the request body.
 *
 * @param {Object} request
 * @protected
 */
Strategy.prototype.authenticate = function (request) {
  if (
    !request.body
    || !request.body.client_assertion_type
    || !request.body.client_assertion
  ) {
    return this.fail();
  }
  if (
    request.body.client_assertion_type
    !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  ) {
    return this.fail();
  }
  // Decode the JWT so the header and payload are available,
  // as they contain fields needed to find the corresponding key.
  // Note that at this point,
  // the assertion has not actually been verified.
  // It will be verified later,
  // after the keying material has been retrieved.
  let assertion = request.body.client_assertion;
  let token = jwt.decode(assertion);
  if (!token) {
    return this.fail();
  }
  let header = token.header;
  let payload = token.payload;
  let self = this;

  function doVerifyStep() {
    function verified(error, client, info) {
      if (error) {
        return self.error(error);
      }
      if (!client) {
        return self.fail();
      }
      self.success(client, info);
    }

    // At this point, the assertion has been verified
    // and authentication can proceed.
    // Call the verify callback so the application can find
    // and verify the client instance.
    // Typically, the subject and issuer of the assertion are the same,
    // as the client is authenticating as itself.
    try {
      if (self._passReqToCallback) {
        if (self._key.length === 4) {
          // This variation allows the application to detect the case
          // in which the issuer and subject of the assertion are different,
          // and permit or deny as necessary.
          self._verify(request, payload.iss || header.iss, header, verified);
        }
        else {
          // self._key.length == 3
          self._verify(request, payload.iss || header.iss, verified);
        }
      }
      else {
        if (self._key.length === 3) {
          // This variation allows the application to detect the case
          // in which the issuer and subject of the assertion are different,
          // and permit or deny as necessary.
          self._verify(payload.sub || payload.iss, payload.iss, verified);
        }
        else {
          // self._key.length == 2
          self._verify(payload.sub || payload.iss, verified);
        }
      }
    }
    catch (exception) {
      return self.error(exception);
    }
  }

  function doKeyStep() {
    function keyed(error, key) {
      if (error) {
        return self.error(error);
      }
      if (!key) {
        return self.fail();
      }

      // The key has been retrieved, verify the assertion.
      // `key` is a PEM encoded RSA public key, DSA public key, or X.509 certificate,
      // as supported by Node's `crypto` module.
      let ok = jwt.verify(assertion, key);
      if (!ok) {
        return self.fail();
      }
      doVerifyStep();
    }

    try {
      if (self._passReqToCallback) {
        if (self._key.length === 4) {
          self._key(request, payload.iss || header.iss, header, keyed);
        }
        else {
          // self._key.length == 3
          self._key(request, payload.iss || header.iss, keyed);
        }
      }
      else {
        if (self._key.length === 3) {
          self._key(payload.iss || header.iss, header, keyed);
        }
        else {
          // self._key.length == 2
          self._key(payload.iss || header.iss, keyed);
        }
      }
    }
    catch (exception) {
      return self.error(exception);
    }
  }

  doKeyStep();
};

module.exports = Strategy;
