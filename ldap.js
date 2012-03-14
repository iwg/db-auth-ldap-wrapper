// Usage:
// $ ldapsearch -H ldap://localhost:1389 -x -D cn=username,ou=users -w password -b "o=myhost" objectclass=*
//                                                         ^^^^^^^^
var config = require('./config');
var db = require('mysql-native').createTCPClient(config.dbIP);
var crypto = require('crypto');
var log = [];

db.auto_prepare = true;
db.auth(config.dbPass, config.dbUser);

function now() {
    return +new Date();
}

function need_reset(r) {
    return now() - r.timestamp > config.loginTrialTimeout;
}

function multi_login(r) {
    return now() - r.timestamp <= config.loginTrialTimeout && r.count > config.loginTrialLimit;
}

function db_authenticate(username, password, next) {
    db.query('use ' + config.userDatabase);
    var result = db.execute('SELECT * FROM ' + config.userTableName + ' WHERE name=(?)', [escape(username)]);
    var cnt = 0;
    result.on('row', function (r) {
        cnt++;
        for (var i = 0; i < r.iter; i++) {
            password = crypto.createHash('md5').update(password + r.salt).digest('hex');
        }
        if (password == r.pass) {
            if (log[username]) delete log[username];
            next(0);
        } else {
            if (log[username]) {
                if (need_reset(log[username])) {
                    log[username] = { timestamp: now(), count: 1 };
                } else {
                    log[username].count++;
                }
            } else {
                log[username] = { timestamp: now(), count: 1 };
                next(1);
            }
        }
    });
    result.on('end', function () {
        if (!cnt) next(1);
    });
}

// Authenticate according to the username/password provided
// @return true if the credentials are correct
// @return false if the authentication is failed
function authenticate(username, password, next) {
    // this is just an example which allows any pair of 
    // username/password which are the same
    if (log[username] && multi_login(log[username])) return false;
    else db_authenticate(username, password, next);
}

var ldap = require('ldapjs');

var server = ldap.createServer();

server.bind('ou=users', function (req, res, next) {
    // bind operation guarantees at least there is a pair 'ou=users'
    // which is { ou: 'users' } in the following shifting
    // we expect the first pair to be something like { cn: 'username' }
    var first_pair = req.dn.shift();

    if (!first_pair.cn) return next(new ldap.InvalidCredentialsError());

    authenticate(first_pair.cn, req.credentials, function (err) {
        if (err) return next(new ldap.InvalidCredentialsError());
        else {
            res.end();
            next();
        }
    });
});

// TODO find username by email address
// TODO find public user information by username

server.listen(1389, function () {
    console.log('LDAP server listening at %s', server.url);
});
