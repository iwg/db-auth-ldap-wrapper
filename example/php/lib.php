<?php
error_reporting(E_ALL & ~E_NOTICE);

$config=array();

//服务器地址
$config["serverHost"]="localhost";
$config["serverPort"]=1389;

$ds = ldap_connect($config["serverHost"], $config["serverPort"]);

function authenticate($username,$password){
    global $ds;
    return ldap_bind($ds,"cn=".$username.",ou=users",$password);
}

function getInformation($username){
    global $ds;
    return ldap_search($ds,"ou=users","name=".$username);
}

function getUsername($email){
    global $ds;
    return ldap_search($ds,"ou=email","email=".$email);
}

//$sr=authenticate("cnx","cnx");

?>
