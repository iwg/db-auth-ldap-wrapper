// Usage:
// $ ldapsearch -H ldap://localhost:1389 -x -D cn=username,ou=users -w password -b "o=myhost" objectclass=*
//                                                         ^^^^^^^^

var config = require('./config');
var db = require('mysql-native').createTCPClient(config.dbIP);
var crypto = require('crypto');
var log = [];

db.auto_prepare = true;
ab.auth(config.dbPass, config.dbUser);

// Authenticate according to the username/password provided
// @return true if the credentials are correct
// @return false if the authentication is failed
function authenticate_db(username, password) {
  // TODO
}

function authenticate(username, password) {
  // this is just an example which allows any pair of 
  // username/password which are the same
  // TODO connect with our own user database for authentication
  return username === password;
}

var ldap = require('ldapjs');

var server = ldap.createServer();

server.bind('ou=users', function(req, res, next) {
  // bind operation guarantees at least there is a pair 'ou=users'
  // which is { ou: 'users' } in the following shifting
  // we expect the first pair to be something like { cn: 'username' }
  var first_pair = req.dn.shift();
  
  if (!first_pair.cn)
    return next(new ldap.InvalidCredentialsError());
  
  if (!authenticate(first_pair.cn, req.credentials))
    return next(new ldap.InvalidCredentialsError());
  
  res.end();
  return next();
});

// TODO find username by email address

// TODO find public user information by username

server.listen(1389, function() {
  console.log('LDAP server listening at %s', server.url);
});
