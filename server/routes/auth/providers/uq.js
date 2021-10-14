import passport from "@outlinewiki/koa-passport";
import Router from "koa-router";
import accountProvisioner from "../../../commands/accountProvisioner";
import env from "../../../env";
import passportMiddleware from "../../../middlewares/passport";
import { getAllowedDomains } from "../../../utils/authentication";
import { StateStore } from "../../../utils/passport";
var mod_util = require('util');

const router = new Router();
const providerName = "uq";

export const config = {
  name: "UQ SSO",
  enabled: true
};

function UQSSOStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('UQ SSO authentication strategy requires a verify function');
  passport.Strategy.call(this);
  this.name = providerName;
  this._verify = verify;
}
mod_util.inherits(UQSSOStrategy, passport.Strategy);
UQSSOStrategy.prototype.authenticate = function uqAuth(req) {
  if (req.headers && req.headers['x-kvd-payload']) {
    var data = req.header['x-kvd-payload'];
    var self = this;
    data = JSON.parse(data);
    function verified(err, user, info) {
      if (err) { return self.error(err); }
      if (!user) { return self.fail(info); }
      self.success(user, info);
    }
    this._verify(req, data, verified);
  } else {
    this.fail(new Error('Missing KVD payload header'));
  }
};

passport.use(
  new UQSSOStrategy(
  {
    scopes: ['https://auth.uq.edu.au']
  },
  async function (req, kvdPayload, done) {
    if (typeof(kvdPayload) !== 'object' || kvdPayload === null) {
      return done(new Error('No KVD payload found in request'));
    }
    if (typeof(kvdPayload['user']) !== 'string') {
      return done(new Error('KVD payload does not contain a user'));
    }
    try {
      const result = await accountProvisioner({
        ip: req.ip,
        team: {
          name: 'Wiki',
          domain: 'uq.edu.au',
          subdomain: 'uq'
        },
        user: {
          name: kvdPayload['name'],
          email: kvdPayload['email'],
          username: kvdPayload['user']
        },
        authenticationProvider: {
          name: providerName,
          providerId: 'uq.edu.au'
        },
        authentication: {
          providerId: kvdPayload['user'],
          scopes: ['https://auth.uq.edu.au']
        }
      });
      return done(null, result.user, result);
    } catch (err) {
      return done(err, null);
    }
  }
  )
);

router.get(providerName, passport.authenticate(providerName, {
  successRedirect: `${env.URL}/auth/${providerName}.callback`,
  failureRedirect: '/',
  session: false
}));
router.get(`${providerName}.callback`, passportMiddleware(providerName));

export default router;
