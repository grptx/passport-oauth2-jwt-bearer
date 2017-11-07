passport-oauth2-jwt-bearer
==========================

JSON Web Token (JWT) Bearer Token Profiles for OAuth 2.0 client authentication strategy for [Passport](https://github.com/jaredhanson/passport).

This module lets you authenticate requests containing client credentials in a JWT sent in the
request body's assertion field, as [defined](http://tools.ietf.org/html/draft-jones-oauth-jwt-bearer-01#section-2.1)
by the JSON Web Token (JWT) Bearer Token Profiles for OAuth 2.0 draft.  These credentials are typically used to protect
the token endpoint and used as an alternative to HTTP Basic authentication.  This module is modeled off of Google's OAuth 2.0 [Server to Server Applications](https://developers.google.com/accounts/docs/OAuth2ServiceAccount).  This module can be used with the [oauth2orize-jwt-bearer](https://github.com/xtuple/oauth2orize-jwt-bearer) module to create a JWT OAuth 2.0 exchange scenario server.

## Install
```bash
$ npm install passport-oauth2-jwt-bearer
```
## Usage

#### Configure Strategy

The JSON Web Token (JWT) Bearer Token Profiles for OAuth 2.0 client authentication strategy authenticates clients
using a JWT.  The strategy requires a `verify` callback,
which accepts those credentials and calls `done` providing a client.
```javascript
var ClientJWTBearerStrategy = require('passport-oauth2-jwt-bearer').Strategy;

passport.use(new ClientJWTBearerStrategy(
    function(claimSetIss, done) {
        Clients.findOne({ clientId: claimSetIss }, function (err, client) {
            if (err) { return done(err); }
            if (!client) { return done(null, false); }
            return done(null, client);
        });
    }
));
```
#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'oauth2-jwt-bearer'`
strategy, to authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application, using [OAuth2orize](https://github.com/jaredhanson/oauth2orize)
middleware to implement the token endpoint:
```javascript
app.get('/profile',
    passport.authenticate(['oauth2-jwt-bearer'], { session: false }),
    oauth2orize.token());
```
## Tests
```bash
$ npm install --dev
$ make test
```
## Credits

  - [bendiy](http://github.com/bendiy)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2012-2013 xTuple <[http://www.xtuple.com/](http://www.xtuple.com/)>
