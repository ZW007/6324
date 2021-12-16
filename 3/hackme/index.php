<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

<?php
        include('connect.php');
        if(isset($_COOKIE['hackme']))
        {
                header("Location: members.php");
        }
?>


<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<title>HackMe</title>
<meta name="keywords" content="" />
<meta name="description" content="" />
<link href="style.css" rel="stylesheet" type="text/css" media="screen" />
<?php
	include('header.php');
?>

<div class="post">
	<div class="post-bgtop">
		<div class="post-bgbtm">
			<h2 class="title"><a href="#">Welcome to hackme </a></h2>
				<div class="entry">
		<?php
			if(!isset($_COOKIE['hackme']))
				{
				?>
	           	<form method="post" action="members.php">
				<h2> LOGIN </h2>
				<table>
					<tr> <td> Username </td> <td> <input type="text" name="username" /> </td> </tr>
					<tr> <td> Password </td> <td> <input type="password" name="password" /> </td>  
                    <td> <input type="submit" name = "submit" value="Login" /> </td></tr>
				</table>
				</form>
					
				<hr style=\"color:#000033\" />
					
			<p></p><p>If you are not a member yet, please click <a href = register.php >here</a> to register.</p>
           <?php
				}
		?>
	</div>
	</div>
	</div>
</div>
<!-- end #sidebar -->
	<?php
		include('footer.php');
	?>

</body>
</html>
