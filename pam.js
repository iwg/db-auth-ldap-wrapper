//How to install
//sudo apt-get install libnss-ldap nscd
// /etc/pam.d/system-auth:
//session     optional      pam_mkhomedir.so
//
//
//================================

var config = require('./config');
var db = require('mysql-native').createTCPClient(config.dbHost);
var crypto = require('crypto');

db.auto_prepare = true;
db.auth(config.userTableName, config.dbUser, config.dbPass);

function db_authenticate(username, password, next) {
    db.query('use ' + config.userDatabase);
    var result = db.execute('SELECT * FROM ' + config.userTableName + ' WHERE name=? or email=?', [username, username]);
    var cnt = 0;
    result.on('row', function (r) {
        cnt++;
        for (var i = 0; i < r.iter; i++) {
            password = crypto.createHash('md5').update(password + r.salt).digest('hex');
        }
        if (password == r.pass)
            next(0);
        else next(1);
    });
    result.on('end', function () {
        if (!cnt) next(1);
    });
}

function authenticate(username, password, next) {
    db_authenticate(username, password, next);
}

function getPass(user, pass, next) {
    db.query('use ' + config.userDatabase);
    var result = db.execute('SELECT * FROM ' + config.userTableName + ' WHERE name=?', [user]);
    result.on('row', function (r) {
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

server.bind('ou=login',function(req,res,next){
    console.log('login');
    console.log(req.dn);
    console.log(req.credentials);
    res.end();
    next();
});

function get(filter,next){
    console.log(filter);
    console.log(filter.attribute);
    if(filter.attribute=='uid'||filter.attribute=='memberuid')
        next(filter.value);
    else{
        filter.filters.forEach(function(i){
        if(i.attribute=='uid'||i.attribute=='memberuid')
            next(i.value);
        });
        next(0);
    }
}

server.search('ou=users',function(req,res,next){
    console.log(req.dn);
    get(req.filter,function(userName){
            db.query('use ' + config.userDatabase);
            var result = db.execute('SELECT * FROM ' + config.userTableName + ' WHERE name=?', [userName]);
            var cnt = 0;
            result.on('row', function (r) {
                ++cnt;
                var obj = {
                    dn: 'cn=' + userName + ',ou=login',
                    attributes: {
                        uid: 'ldap_'+userName,
                        uidNumber:20000,
                        gid: 'ldap_'+userName,
                        gidNumber:20000,
                        cn: r.name,
                        sn: 'ldap',
                        display_name: r.display_name,
                        email: r.email,
                        objectclass: 'top',
                        objectclass: 'person',
                        objectclass: 'posixAccount',
                        objectclass: 'shadowAccount',
                        homeDirectory: '/home/'+userName,
                        loginShell: '/bin/bash'
                    }
                };
                res.send(obj);
            });
            result.on('end',function(){
                res.end();
                next();
            });
    });
});

server.listen(389, function () {
    console.log('LDAP server listening at %s', server.url);
});
