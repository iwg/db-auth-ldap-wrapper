<center>LDAP for iwg</center>
====================
***
LDAP for iwg is a *Node.JS* project that design for iwg to control permission.

###How to install NodeJS

Just download from [nodejs](nodejs.org).

If you are using Ubuntu:

    sudo apt-get install zlib1g-dev

    sudo apt-get install libssl-dev

    ./configure

    make

    make install

If you are using Windows:

    just run the msi file to install

###How to install npm(the tools for manage modules using in NodeJS)

You can refer the following urls:

[教學 nodeJS - npm install on linux and windows ](http://clonn.blogspot.com/2011/01/nodejs-npm.html)

[在Windows平台上安装Node.js及NPM模块管理](http://www.cnblogs.com/seanlv/archive/2011/11/22/2258716.html)

###How to install ldap for PHP?

If you are using Ubuntu, just run the following command in Terminal:

    sudo apt-get install php5-ldap

If you are using windows, just edit the php.ini:

change
    
    ;extension=php_ldap.dl

to
    
    extension=php_ldap.dl

and restart Apache. You can visit the phpinfo() page to check it.

###How to get, install, and run this application?

    sudo npm install ldapjs
    
    cd ~/node_modules/
    
    git clone https://github.com/sidorares/nodejs-mysql-native
    
    mv nodejs-mysql-native mysql-native
    
    cd ~/db-auth-ldap-wrapper/
    
    node ldap.js
