<html>
<body>
<?php
    // Connects to the Database 
	include('../hackme/connect.php');
	connect();
	
	//if the form is submitted 
	if (isset($_POST['post_submit'])) {
		
		$_POST['title'] = trim($_POST['title']);
		if(!$_POST['title'] | !$_POST['message']) {
			include('../hackme/header.php');
			die('<p>You did not fill in a required field.
			Please go back and try again!</p>');
		}
		
	mysql_query("INSERT INTO threads (username, title, message, date) VALUES('".$_COOKIE['hackme']."', '". $_POST['title']."', '". $_POST[message]."', '".time()."')")or die(mysql_error());	
		
	header("Location: ../hackme/members.php");
	}
?> 
</body>
</html>

