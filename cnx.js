// Usage:
//
// Authenticate:
// ldapsearch -H ldap://localhost:1389 -x -D cn=username,ou=users -w password
//
// username->Information:
// ldapsearch -H ldap://localhost:1389 -x -D cn=username,ou=users -w password -b "ou=users" name=cnx
//
// emailAddress->username:
// ldapsearch -H ldap://localhost:1389 -x -b "ou=email" email=emailAddress
//
// change information
// ldapmodify -x -H ldap://localhost:1389 -D cn=username,ou=users -w password
// dn:cn=username,ou=users
// changetype:modify
// replace: key
// key: value
// -
// replace: xxx
// xxx:yyy
// -
// ...(so on)
//
// don't forget to change the config defined in config.js
var config = require('./config');
var db = require('mysql').createConnection({
    host: config.dbHost,
    user: config.dbUser,
    password: config.dbPass,
    database: config.userDatabase
});
var crypto = require('crypto');
var log = [];

function now() {
    return +new Date();
}

function need_reset(r) {
    return now() - r.timestamp > config.loginTrialTimeout;
}

function multi_login(r) {
    return !need_reset(r) && r.count > config.loginTrialLimit;
}

function new_log() {
    return {
        timestamp: now(),
        count: 1
    };
}

function db_authenticate(username, password, next) {
    var result = db.query('SELECT * FROM ' + config.userTableName + ' WHERE name=? or email=?', [username, username]);
    var cnt = 0;
    result.on('result', function (r) {
        cnt++;
        for (var i = 0; i < r.iter; i++) {
            password = crypto.createHash('md5').update(password + r.salt).digest('hex');
        }
        if (password == r.pass) {
            if (log[username]) delete log[username];
            next(0);
        } else if (log[username]) {
            if (need_reset(log[username])) {
                log[username] = new_log();
            } else {
                log[username].count++;
                next(1);
            }
        } else {
            log[username] = new_log();
            next(1);
        }
    }).on('end', function () {
        if (!cnt) next(1);
    });
}

function authenticate(username, password, next) {
    if (log[username] && multi_login(log[username])) next(1);
    else db_authenticate(username, password, next);
}

function getPass(user, pass, next) {
    var result = db.query('SELECT * FROM ' + config.userTableName + ' WHERE name=?', [user]);
    result.on('result', function (r) {
        var iter = r.iter;
        var salt = r.salt;
        for (var i = 0; i < iter; i++) {
            pass += salt;
            pass = crypto.createHash("md5").update(pass).digest("hex");
        }
        next(pass);
    });
}

var ldap = require('ldapjs');

var server = ldap.createServer();

server.bind('ou=users', function (req, res, next) {
    var first_pair = req.dn.rdns[0];

    if (!first_pair.cn) return next(new ldap.InvalidCredentialsError());

    authenticate(first_pair.cn, req.credentials, function (err) {
        if (err) return next(new ldap.InvalidCredentialsError());
        else {
            res.end();
            next();
        }
    });
});

server.search('ou=email', function (req, res, next) {

    var emailAddress = req.filter.value;
    var result = db.query('SELECT * FROM ' + config.userTableName + ' WHERE email=?', [emailAddress]);
    var cnt = 0;
    result.on('result', function (r) {
        ++cnt;
        var obj = {
            dn: 'user=' + r.name,
            attributes: {
                user: r.name,
                objectclass: 'user'
            }
        };
        res.send(obj);
    }).on('end', function (r) {
        res.end();
        next();
    });
});

server.search('ou=users', function (req, res, next) {

    var userName = req.filter.value;
    var result = db.query('SELECT * FROM ' + config.userTableName + ' WHERE name=?', [userName]);
    var cnt = 0;
    result.on('result', function (r) {
        ++cnt;
        var obj = {
            dn: 'user=' + userName,
            attributes: {
                id: r.id,
                user: r.name,
                display_name: r.display_name,
                email: r.email,
                objectclass: 'user'
            }
        };
        res.send(obj);
    }).on('end', function (r) {
        res.end();
        next();
    });
});

server.modify('ou=users', function (req, res, next) {
    var user = req.dn.rdns[0]['cn'];
    var b_user = req.connection.ldap.bindDN.rdns[0]['cn'];

    if (user != b_user) return next(new ldap.InsufficientAccessRightsError());
    req.changes.forEach(function (c) {
        if (c.operation == 'replace') {
            var key = c.modification.type;
            var value = c.modification.vals[0];
            if (key == "pass") {
                value = getPass(user, value, function (pass) {
                    db.query('UPDATE ' + config.userTableName + ' SET pass = ? WHERE name= ?', [pass, user]);
                });
            } else {
                db.query('UPDATE ' + config.userTableName + ' SET ' + db.escape(key) + ' = ? WHERE name= ?', [value, user]);
            }
        }
    });
    res.end();
});

server.listen(1389, function () {
    console.log('LDAP server listening at %s', server.url);
});
