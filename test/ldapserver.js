'use strict';
var ldap = require('ldapjs');
var debug = require('debug')('passport-ldap:ldapserver');

var authorize = function(req, res, next) {
  return next();
};

var SUFFIX = 'cn=valid,ou=passport-ldap';
var server = null;

var db = {
  'valid': {
    dn: 'cn=valid, ou=passport-ldap',
    attributes:  {
      uid:  'valid',
      name: 'Valid User'
    }
  }
};

exports.start = function(port, cb) {
  if (server) {
    if (typeof cb === 'function') {
      return cb();
    }
    return;
  }

  server = ldap.createServer();

  server.bind(SUFFIX, authorize, function(req, res, next) {
    var dn = req.dn.toString();
    if (dn !== 'cn=valid, ou=passport-ldap' || req.credentials !== 'valid') {
      return next(new ldap.InvalidCredentialsError());
    }
    res.end();
    return next();
  });

  server.search(SUFFIX, authorize, function(req, res, next) {
    debug('SEARCH', /memberof/.test(req.attributes));

    if(/memberof/.test(req.attributes)) {
      debug('NO RESULT');
    } else if (req.filter.attribute === 'uid' && req.filter.value === 'valid') {
      debug('res.send', req.filter);
      res.send(db.valid);
    } else if (req.filter.attribute === 'member' && req.filter.value === db.valid.dn) {
      debug('res.send2', req.filter);
      res.send({
        dn: 'cn=Group 1, ou=passport-ldap',
        attributes: {
          name: 'Group 1'
        }
      });
      res.send({
        dn: 'cn=Group 2, ou=passport-ldap',
        attributes: {
          name: 'Group 2'
        }
      });
    }
    res.end();
    return next();
  });

  server.listen(port, function() {
    debug('SERVER listen: %s', port);
    if (typeof cb === 'function') {
      return cb();
    }
  });
};

exports.close = function(cb) {
  if (server) {
    server.close();
  }
  server = null;
  if (typeof cb === 'function') {
    return cb();
  }
  return;
};

if (!module.parent) {
  exports.start(1389);
}
