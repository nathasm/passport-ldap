'use strict';
var should       = require('chai').Should();
var LdapStrategy = require('passport-ldap');
var Strategy     = LdapStrategy.Strategy;
var request      = require('supertest');
var ldapserver   = require('./ldapserver');
var server       = require('./server');

var LDAP_PORT = 1389;

var expressapp = null;
var verify = function() {};

// Base options that are cloned where needed to edit
var BASE_OPTS = {
  server: {
    url: 'ldap://localhost:' +  LDAP_PORT.toString(),
  },
  authMode: 1,
  base: 'ou=passport-ldap',
  uidTag: 'cn',
  search: {
    filter: '(uid=$uid$)'
  }
};

var start_servers = function(opts) {
  return function(cb) {
    ldapserver.start(LDAP_PORT, function() {
      server.start(opts, function(app) {
        expressapp = app;
        cb();
      });
    });
  };
};

var stop_servers = function(cb) {
  server.close(function() {
    ldapserver.close(function() {
      cb();
    });
  });
};

describe('LDAP authentication strategy', function() {
  var opts;
  beforeEach(function() {
    opts = BASE_OPTS;
  });

  describe('by itself', function() {

    it('should export Strategy constructor directly', function(cb) {
      require('passport-ldap').should.be.a('object');
      cb();
    });

    it('should export Strategy constructor separately as well', function(cb) {
      Strategy.should.be.a('function');
      (function() {
        var s = new Strategy(opts, verify);
      }).should.not.throw(Error);
      cb();
    });

    it('should throw error if not verify function is present', function(cb) {
      Strategy.should.be.a('function');
      (function() {
        var s = new Strategy(opts);
      }).should.throw(Error);
      cb();
    });

    it('should be named ldapauth', function(cb) {
      var s = new Strategy(opts, verify);
      s.name.should.equal('ldap');
      cb();
    });

    it('should throw an error if no arguments are provided', function(cb) {
      (function() {
        var s = new Strategy();
      }).should.throw(Error);
      cb();
    });

    it('should throw an error if options are not accepted by ldap', function(cb) {
      (function() {
        var s = new Strategy({}, verify);
      }).should.throw(Error);
      cb();
    });

    it('should initialize proper parameters', function(cb) {
      (function() {
        var s = new Strategy(opts, verify);
      }).should.not.throw(Error);
      cb();
    });

    describe("with basic settings", function() {

      before(start_servers(BASE_OPTS));

      after(stop_servers);

      it("should return unauthorized if credentials are not given", function(cb) {
        request(expressapp)
        .post('/login')
        .send({})
        .expect(401)
        .end(cb);
      });

      it("should allow access with valid credentials", function(cb) {
        request(expressapp)
        .post('/login')
        .send({user: 'valid', pwd: 'valid'})
        .expect(200)
        .end(cb);
      });

      it("should not allow access with valid credentials in query string", function(cb) {
        request(expressapp)
        .post('/login?user=valid&pwd=valid')
        .expect(401)
        .end(cb);
      });

      it("should return unauthorized with invalid credentials", function(cb) {
        request(expressapp)
        .post('/login')
        .send({user: 'valid', pwd: 'invalid'})
        .expect(401)
        .end(cb);
      });

      it("should return unauthorized with non-existing user", function(cb) {
        request(expressapp)
        .post('/login')
        .send({user: 'nonexisting', pwd: 'invalid'})
        .expect(401)
        .end(cb);
      });
    });
  });

  describe('with custom settings', function() {
    var OPTS = JSON.parse(JSON.stringify(BASE_OPTS));
    OPTS.search.attributes = [ 'memberOf' ];
    before(start_servers(OPTS));
    after(stop_servers);
    it('should return unauthorized if can bind but no matching attributes', function(cb) {
        request(expressapp)
        .post('/login')
        .send({user: 'valid', pwd: 'valid'})
        .expect(401)
        .end(cb);
    });
  });
});
