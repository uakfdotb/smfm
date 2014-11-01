<?php

/*
    This file is part of smfm.

    smfm is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    smfm is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with smfm.  If not, see <http://www.gnu.org/licenses/>.
*/

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

if(isset($config['smfm_includes']) && is_array($config['smfm_includes'])) {
	foreach($config['smfm_includes'] as $include_file) {
		require_once(dirname(__FILE__) . '/' . $include_file);
	}
}

?>
