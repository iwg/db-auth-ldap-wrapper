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
    $sr=ldap_search($ds,"ou=users","name=".$username);
    return ldap_get_entries($ds, $sr);
}

function getUsername($email){
    global $ds;
    $sr=ldap_search($ds,"ou=email","email=".$email);
    return ldap_get_entries($ds, $sr);
}

//$sr=authenticate("cnx","cnx");
//print_r(getInformation("cnx"));

?>
