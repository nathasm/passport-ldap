'use strict';
var express      = require('express');
var passport     = require('passport');
var LdapStrategy = require('passport-ldap').Strategy;
var bodyParser   = require('body-parser');

var server = null;

passport.serializeUser(function(user, cb) {
  cb(null, user.dn);
});

passport.deserializeUser(function(dn, cb) {
  cb(null, {dn: dn});
});

exports.start = function(opts, cb) {

  var app = express();

  passport.use(new LdapStrategy(opts, function(user, cb) {
    return cb(null, user);
  }));

  app.use(bodyParser.json());
  app.use(passport.initialize());

  app.post('/login', function(req, res, next) {
    return passport.authenticate('ldap', function(err, user, info){
      if (err) { return next(err.stack); }
      if (!user) { return res.status(401).json(user); }
      req.logIn(user, function(err) {
        if ( err ) { return next(err.stack); }
        return res.json(user);
      });
    })(req, res, next);
  });

  if (typeof cb === 'function') { return cb(app); }
  return;
};

exports.close = function(cb) {
  if (server) { server.close(); }
  server = null;
  if (typeof cb === 'function') { return cb(); }
  return;
};
