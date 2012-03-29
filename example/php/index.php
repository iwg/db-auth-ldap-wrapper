<?php include('lib.php');?>
<html lang="en">
<head>
<meta charset="utf-8">
<title>cnx's ldap test</title>
<body>
    <script>
        function print(message){
            <?php 
            echo message;
            ?>
        }
    </script>
    <p>帐号:<input type="text" id="username1"/></p>
    <p>密码:<input type="password" id="password1"/></p>
    <input type="button" onclick="">
    
    <br><br>
    
    <p>帐号:<input type="text" id="username2"/></p>
    <input type="button" onclick="">
    
    <br><br>
    
    <p>email地址:<input type="text" id="email"/></p>
    <input type="button" onclick="">
</body>
</html>
