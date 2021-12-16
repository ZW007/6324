<?php
setcookie(hackme, "", time() - 3600);
setcookie(hackme_pass, "", time() - 3600);
header("Location: index.php");
?>
