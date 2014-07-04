<?php

function smfm_error($errno, $errstr, $errfile, $errline) {
	error_log("smfm_error: [$errno] $errstr encountered on line $errline in file $errfile, aborting.");
	die('Encountered error.');
}

if(php_sapi_name() !== 'cli') {
	//require PHP >= 5.4
	// if we didn't have this check, user would see syntax errors instead :)
	if(version_compare(phpversion(), '5.4') < 0) {
		die('smfm requires PHP >= 5.4 -- you are running ' . phpversion() . '!');
	}

	//require short open tags
	if(ini_get('short_open_tag') != 1) {
		die('smfm requires short_open_tag = On');
	}
}

require_once(dirname(__FILE__) . "/config.php");
require_once(dirname(__FILE__) . "/common.php");
require_once(dirname(__FILE__) . "/database.php");

if(!isset($GLOBALS['SMFM_ISSCRIPT']) || !$GLOBALS['SMFM_ISSCRIPT']) {
	require_once(dirname(__FILE__) . "/session.php");
}

require_once(dirname(__FILE__) . "/sanitize.php");

set_error_handler('smfm_error', (E_ALL & ~E_STRICT) & ~E_DEPRECATED);

?>
