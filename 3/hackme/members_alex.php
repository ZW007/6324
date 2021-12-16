<?php
	// Connects to the Database 
	include('connect.php');
	connect();
	
	//if the login form is submitted 
	if (isset($_POST['submit'])) {
		
		$_POST['username'] = trim($_POST['username']);
		if(!$_POST['username'] | !$_POST['password']) {
			die('<p>You did not fill in a required field.
			Please go back and try again!</p>');
		}
		
        //hash add salt !!
		$passwordHash = password_hash($_POST['password'],PASSWORD_DEFAULT);
		
		$check = mysql_query("SELECT * FROM users WHERE username = '".$_POST['username']."'")or die(mysql_error());
		$pass_fetched = mysql_query("SELECT pass FROM users WHERE username = '".$_POST['username']."'")or die(mysql_error());
        $pass_row = mysql_fetch_row($pass_fetched);
        // same with member.php line 21
        // $num_rows = mysql_num_rows($pass_row);
        $check1 = password_verify($_POST['password'],$pass_row[0]);
  
 		//Gives error if user already exist
 		$check2 = mysql_num_rows($check);
		if ($check2 == 0 || $check1 == false) {
			die("<p>Sorry, user name and/or password error.$pass_fetched,  $passwordHash</p>");
		}
		else
		{
			$hour = time() + 3600; 
            // same site prevention !!
			setcookie(hackme, $_POST['username'], $hour,'/~zxw180035; SameSite=strict'); 
			//setcookie(hackme_pass, $passwordHash, $hour,'/~zxw180035; SameSite=strict');
      
			header("Location: members.php");
		}
	}
		?>  
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>hackme</title>
<link href="style.css" rel="stylesheet" type="text/css" media="screen" />
<?php
	include('header.php');
?>
<div class="post">
	<div class="post-bgtop">
		<div class="post-bgbtm">
        <h2 class = "title">hackme bulletin board</h2>
        	<?php
          //echo '<script type="text/javascript">alert("'.$_COOKIE['hackme'].'");</script>';
            if(!isset($_COOKIE['hackme'])){
				 die('Why are you not logged in?!');
			}else
			{
				print("<p>Logged in as <a>$_COOKIE[hackme]</a></p>");
			}
			?>
        </div>
    </div>
</div>

<?php
	$threads = mysql_query("SELECT * FROM threads ORDER BY date DESC")or die(mysql_error());
	while($thisthread = mysql_fetch_array( $threads )){
?>
	<div class="post">
	<div class="post-bgtop">
	<div class="post-bgbtm">
		<h2 class="title"><a href="show.php?pid=<?php echo $thisthread['id'] ?>"><?php echo $thisthread['title']?></a></h2>
							<p class="meta"><span class="date"> <?php echo date('l, d F, Y',$thisthread[date]) ?> - Posted by <a href="#"><?php echo $thisthread[username] ?> </a></p>

	</div>
	</div>
	</div> 

<?php
}
	include('footer.php');
?>
</body>
</html>







<!-- <?php
	// Connects to the Database 
	include('connect.php');
	connect();
	
	//if the login form is submitted 
	if (isset($_POST['submit'])) {
		
		$_POST['username'] = trim($_POST['username']);
		if(!$_POST['username'] | !$_POST['password']) {
			die('<p>You did not fill in a required field.
			Please go back and try again!</p>');
		}
		
        //hash add salt !!
		$passwordHash = password_hash($_POST['password'],PASSWORD_DEFAULT);
		
		$check = mysql_query("SELECT * FROM users WHERE username = '".$_POST['username']."'")or die(mysql_error());
		$result = mysql_query("SELECT pass FROM users WHERE username = '".$_POST['username']."'")or die(mysql_error());
    $result2 = mysql_fetch_row($result);
    // same to member.php line 21
    $check3 = password_verify($_POST['password'],$result2[0]);
  
 		//Gives error if user already exist
 		$check2 = mysql_num_rows($check);
		if ($check2 == 0 || $check3 == false) {
			die("<p>Sorry, user name does not exisits or password incorrect.</p>");
		}
		else
		{
			$hour = time() + 3600; 
            // same site prevention !!
			setcookie(hackme, $_POST['username'], $hour,'/~axg156230; SameSite=strict'); 
			//setcookie(hackme_pass, $passwordHash, $hour,'/~axg156230; SameSite=strict');
      
			header("Location: members.php");
		}
	}
		?>  
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>hackme</title>
<link href="style.css" rel="stylesheet" type="text/css" media="screen" />
<?php
	include('header.php');
?>
<div class="post">
	<div class="post-bgtop">
		<div class="post-bgbtm">
        <h2 class = "title">hackme bulletin board</h2>
        	<?php
          //echo '<script type="text/javascript">alert("'.$_COOKIE['hackme'].'");</script>';
            if(!isset($_COOKIE['hackme'])){
				 die('Why are you not logged in?!');
			}else
			{
				print("<p>Logged in as <a>$_COOKIE[hackme]</a></p>");
			}
			?>
        </div>
    </div>
</div>

<?php
	$threads = mysql_query("SELECT * FROM threads ORDER BY date DESC")or die(mysql_error());
	while($thisthread = mysql_fetch_array( $threads )){
?>
	<div class="post">
	<div class="post-bgtop">
	<div class="post-bgbtm">
		<h2 class="title"><a href="show.php?pid=<?php echo $thisthread['id'] ?>"><?php echo $thisthread['title']?></a></h2>
							<p class="meta"><span class="date"> <?php echo date('l, d F, Y',$thisthread[date]) ?> - Posted by <a href="#"><?php echo $thisthread[username] ?> </a></p>

	</div>
	</div>
	</div> 

<?php
}
	include('footer.php');
?>
</body>
</html>

 -->
