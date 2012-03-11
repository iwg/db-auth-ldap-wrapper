// Usage:
// $ ldapsearch -H ldap://localhost:1389 -x -D cn=username,ou=users -w password -b "o=myhost" objectclass=*
//                                                         ^^^^^^^^

var config=require("./config");
var db=require("mysql-native").createTCPClient(config.dbHost);
var crypto=require('crypto');
var log=[];
var now=new Date();

db.auto_prepare=true;
db.auth(config.dbPass,config.dbUser);

// Authenticate according to the username/password provided
// @return true if the credentials are correct
// @return false if the authentication is failed

function need_To_Reset(record){
    return now.getTime-record.timestamp>config.loginTrialTimeout;
}

function multi_Login(record){
    return now.getTime()-record.timestamp<=config.loginTrialTimeout && record.count>config.loginTrialLimit;
}

function authenticate_db(username,password){
  db.query("use "+config.userTableName);
  var result=db.query("SELECT * FROM ? WHERE name=?", [config.userDatabase, escape(username)]);
  var cnt=0;
  result.on('row',function(r){
    ++cnt;
    var iter=r.iter;
    var salt=r.salt;
    for(var i=0;i<iter;i++){
      password+=salt;
      password=crypto.createHash("md5").update(password).digest("hex");
    }
    if(password==r.pass){
      if(log[username])delete log[username];
      return true;
    }
    else{
      if(log[username]){
        if(need_To_Reset(log[username])){
          log[username]={
            timestamp:now.getTime(),
            count:1
          };
        }
        else{
          ++log[username].count;
        }
      }
      else{
        log[username]={
          timestamp:now.getTime(),
          count:1
        };
        return false;
      }
    }
  });
  result.on('end',function(){
    if(!cnt)
      return false;
  });
}

function authenticate(username, password) {
  // this is just an example which allows any pair of 
  // username/password which are the same
  // TODO connect with our own user database for authentication
  //return username === password;
  if(log[username]){
    var timestamp=log[username].timestamp;
    var count=log[username].count;
    if(multi_Login())return false;
    return authenticate_db(username,password);
  }
  else return authenticate_db(username,password);
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
