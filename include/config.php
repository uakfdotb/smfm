<?php

//get static configuration values
//these are configuration settings not set from the database
// for example, database settings... :)
if(file_exists(dirname(__FILE__) . '/../config.php')) {
	require_once(dirname(__FILE__) . '/../config.php');
} else {
	die("Server configuration error: config.php does not exist.");
}

?>
