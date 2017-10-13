var vows = require('vows');
var assert = require('assert');
var util = require('util');
var ClientJWTBearerStrategy = require('passport-oauth2-jwt-bearer/strategy');

function base64urlEncode(str) {
  return base64urlEscape(new Buffer(str).toString('base64'));
}

function base64urlEscape(str) {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

vows.describe('ClientJWTBearerStrategy').addBatch({

  'strategy': {
    topic: function() {
      return new ClientJWTBearerStrategy(function(){});
    },

    'should be named oauth2-client-password': function (strategy) {
      assert.equal(strategy.name, 'oauth2-jwt-bearer');
    }
  },

  'strategy handling a request': {
    topic: function() {
      var strategy = new ClientJWTBearerStrategy(function(claimSetIss, done) {
        if (claimSetIss == 'c1234') {
          done(null, { id: claimSetIss });
        } else {
          done(null, false);
        }
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        var header = {"alg":"RS256","typ":"JWT"};
        var claimSet = {"iss": "c1234"};
        var signature = 'some-fake-sig';
        var contents = [];

        contents.push(base64urlEncode(JSON.stringify(header)));
        contents.push(base64urlEncode(JSON.stringify(claimSet)));
        contents.push(signature);

        strategy.success = function(user) {
          self.callback(null, user);
        };
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        };
        strategy.error = function() {
          self.callback(new Error('should-not-be-called'));
        };

        req.body = {};
        req.body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        req.body['client_assertion'] = contents.join('.');
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.id, 'c1234');
      }
    }
  },

  'strategy that verifies a request with additional info': {
    topic: function() {
      var strategy = new ClientJWTBearerStrategy(function(claimSetIss, done) {
        if (claimSetIss == 'c1234') {
          done(null, { id: claimSetIss }, { foo: 'bar' });
        } else {
          done(null, false);
        }
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        var header = {"alg":"RS256","typ":"JWT"};
        var claimSet = {"iss": "c1234"};
        var signature = 'some-fake-sig';
        var contents = [];

        contents.push(base64urlEncode(JSON.stringify(header)));
        contents.push(base64urlEncode(JSON.stringify(claimSet)));
        contents.push(signature);

        strategy.success = function(user, info) {
          self.callback(null, user, info);
        };
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        };
        strategy.error = function() {
          self.callback(new Error('should-not-be-called'));
        };

        req.body = {};
        req.body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        req.body['client_assertion'] = contents.join('.');
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.id, 'c1234');
      },
      'should authenticate with additional info' : function(err, user, info) {
        assert.equal(info.foo, 'bar');
      }
    }
  },

  'strategy handling a request that is not verified': {
    topic: function() {
      var strategy = new ClientJWTBearerStrategy(function(claimSetIss, done) {
        done(null, false);
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        var header = {"alg":"RS256","typ":"JWT"};
        var claimSet = {"iss": "c1234"};
        var signature = 'some-fake-sig';
        var contents = [];

        contents.push(base64urlEncode(JSON.stringify(header)));
        contents.push(base64urlEncode(JSON.stringify(claimSet)));
        contents.push(signature);

        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        };
        strategy.fail = function() {
          self.callback(null);
        };
        strategy.error = function() {
          self.callback(new Error('should-not-be-called'));
        };

        req.body = {};
        req.body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        req.body['client_assertion'] = contents.join('.');
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should fail authentication' : function(err, user) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
      }
    }
  },

  'strategy that errors while verifying request': {
    topic: function() {
      var strategy = new ClientJWTBearerStrategy(function(claimSetIss, done) {
        done(new Error('something went wrong'));
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        var header = {"alg":"RS256","typ":"JWT"};
        var claimSet = {"iss": "c1234"};
        var signature = 'some-fake-sig';
        var contents = [];

        contents.push(base64urlEncode(JSON.stringify(header)));
        contents.push(base64urlEncode(JSON.stringify(claimSet)));
        contents.push(signature);

        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        };
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        };
        strategy.error = function(err) {
          self.callback(null, err);
        };

        req.body = {};
        req.body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        req.body['client_assertion'] = contents.join('.');
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
        assert.equal(e.message, 'something went wrong');
      }
    }
  },

  'strategy handling a request without a body': {
    topic: function() {
      var strategy = new ClientJWTBearerStrategy(function(claimSetIss, done) {
        done(null, false);
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        var header = {"alg":"RS256","typ":"JWT"};
        var claimSet = {"iss": "c1234"};
        var signature = 'some-fake-sig';
        var contents = [];

        contents.push(base64urlEncode(JSON.stringify(header)));
        contents.push(base64urlEncode(JSON.stringify(claimSet)));
        contents.push(signature);

        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        };
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        };
        strategy.error = function() {
          self.callback(new Error('should-not-be-called'));
        };

        //req.body = {};
        //req.body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        //req.body['client_assertion'] = contents.join('.');
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not call success or error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should fail authentication with default status' : function(err, challenge, status) {
        assert.isUndefined(challenge);
      }
    }
  },

  'strategy handling a JWT without a claimSet.iss': {
    topic: function() {
      var strategy = new ClientJWTBearerStrategy(function(claimSetIss, done) {
        done(null, false);
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        var header = {"alg":"RS256","typ":"JWT"};
        var claimSet = {"other": "claim"};
        var signature = 'some-fake-sig';
        var contents = [];

        contents.push(base64urlEncode(JSON.stringify(header)));
        contents.push(base64urlEncode(JSON.stringify(claimSet)));
        contents.push(signature);

        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        };
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        };
        strategy.error = function() {
          self.callback(new Error('should-not-be-called'));
        };

        req.body = {};
        req.body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        req.body['client_assertion'] = contents.join('.');
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not call success or error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should fail authentication with default status' : function(err, challenge, status) {
        assert.isUndefined(challenge);
      }
    }
  },

  'strategy handling a JWT without a claimSet': {
    topic: function() {
      var strategy = new ClientJWTBearerStrategy(function(claimSetIss, done) {
        done(null, false);
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        var header = {"alg":"RS256","typ":"JWT"};
        //var claimSet = {"iss": "c1234"};
        var signature = 'some-fake-sig';
        var contents = [];

        contents.push(base64urlEncode(JSON.stringify(header)));
        //contents.push(base64urlEncode(JSON.stringify(claimSet)));
        contents.push(signature);

        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        };
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        };
        strategy.error = function() {
          self.callback(new Error('should-not-be-called'));
        };

        req.body = {};
        req.body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        req.body['client_assertion'] = contents.join('.');
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not call success or error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should fail authentication with default status' : function(err, challenge, status) {
        assert.isUndefined(challenge);
      }
    }
  },

  'strategy handling a JWT without a header': {
    topic: function() {
      var strategy = new ClientJWTBearerStrategy(function(claimSetIss, done) {
        done(null, false);
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        //var header = {"alg":"RS256","typ":"JWT"};
        var claimSet = {"iss": "c1234"};
        var signature = 'some-fake-sig';
        var contents = [];

        //contents.push(base64urlEncode(JSON.stringify(header)));
        contents.push(base64urlEncode(JSON.stringify(claimSet)));
        contents.push(signature);

        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        };
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        };
        strategy.error = function() {
          self.callback(new Error('should-not-be-called'));
        };

        req.body = {};
        req.body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        req.body['client_assertion'] = contents.join('.');
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not call success or error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should fail authentication with default status' : function(err, challenge, status) {
        assert.isUndefined(challenge);
      }
    }
  },

  'strategy handling a JWT without a signature': {
    topic: function() {
      var strategy = new ClientJWTBearerStrategy(function(claimSetIss, done) {
        done(null, false);
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        var header = {"alg":"RS256","typ":"JWT"};
        var claimSet = {"iss": "c1234"};
        //var signature = 'some-fake-sig';
        var contents = [];

        contents.push(base64urlEncode(JSON.stringify(header)));
        contents.push(base64urlEncode(JSON.stringify(claimSet)));
        //contents.push(signature);

        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        };
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        };
        strategy.error = function() {
          self.callback(new Error('should-not-be-called'));
        };

        req.body = {};
        req.body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        req.body['client_assertion'] = contents.join('.');
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not call success or error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should fail authentication with default status' : function(err, challenge, status) {
        assert.isUndefined(challenge);
      }
    }
  },

  'strategy constructed without a verify callback': {
    'should throw an error': function () {
      assert.throws(function() { new ClientJWTBearerStrategy(); });
    }
  },

  'strategy with passReqToCallback=true option': {
    topic: function() {
      var strategy = new ClientJWTBearerStrategy({passReqToCallback:true}, function(req, claimSetIss, done) {
        assert.isNotNull(req);
        if (claimSetIss == 'c1234') {
          done(null, { id: claimSetIss });
        } else {
          done(null, false);
        }
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        var header = {"alg":"RS256","typ":"JWT"};
        var claimSet = {"iss": "c1234"};
        var signature = 'some-fake-sig';
        var contents = [];

        contents.push(base64urlEncode(JSON.stringify(header)));
        contents.push(base64urlEncode(JSON.stringify(claimSet)));
        contents.push(signature);

        strategy.success = function(user) {
          self.callback(null, user);
        };
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        };
        strategy.error = function() {
          self.callback(new Error('should-not-be-called'));
        };

        req.body = {};
        req.body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        req.body['client_assertion'] = contents.join('.');
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.id, 'c1234');
      }
    }
  }

}).export(module);
