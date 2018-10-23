var vows = require('vows');
var assert = require('assert');
var util = require('util');
var clientJWTBearer = require('passport-oauth2-jwt-bearer');

vows.describe('passport-oauth2-jwt-bearer').addBatch({

  'module': {
    'should report a version': function (x) {
      assert.isString(clientJWTBearer.version);
    },

    'should export Strategy': function (x) {
      assert.isFunction(clientJWTBearer.Strategy);
    }
  }

}).export(module);
