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

function store_in_session($key, $value) {
	if(isset($_SESSION)) {
		$_SESSION[$key] = $value;
	}
}

function unset_session($key) {
	$_SESSION[$key]=' ';
	unset($_SESSION[$key]);
}

function get_from_session($key) {
	if(isset($_SESSION)) {
		if(isset($_SESSION[$key])) {
			 return $_SESSION[$key];
		} else {
			return ''; //key not set, CSRF validation failure
		}
	}
	else { //no session data, no CSRF risk
		return false;
	}
}

function csrfguard_generate_token($unique_form_name) {
	if(function_exists("hash_algos") and in_array("sha512",hash_algos())) {
		$token = hash("sha512", mt_rand(0, mt_getrandmax()));
	} else {
		$token=' ';
		for ($i = 0; $i < 128; $i++) {
			$r=mt_rand(0,35);
			if ($r<26) {
				$c = chr(ord('a') + $r);
			}
			else {
				$c = chr(ord('0') + $r - 26);
			}
			$token .= $c;
		}
	}

	store_in_session($unique_form_name, $token);
	return $token;
}

function csrfguard_validate_token($unique_form_name, $token_value) {
	$token = get_from_session($unique_form_name);

	if($token === false) {
		return true;
	} else if($token == $token_value) {
		$result = true;
	} else {
		$result = false;
	}

	unset_session($unique_form_name);
	return $result;
}

function csrfguard_replace_forms($form_data_html) {
	$count=preg_match_all("/<form(.*?)>(.*?)<\\/form>/is", $form_data_html, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
	if(is_array($matches)) {
		$matches = array_reverse($matches);

		foreach($matches as $m) {
			if(strpos($m[1][0],"nocsrf")!==false) {
				continue;
			}

			$name = "CSRFGuard_" . mt_rand(0, mt_getrandmax());
			$token = csrfguard_generate_token($name);
			$form_data_html = substr_replace($form_data_html,
				"<form{$m[1][0]}>
<input type='hidden' name='CSRFName' value='{$name}' />
<input type='hidden' name='CSRFToken' value='{$token}' />{$m[2][0]}</form>", $m[0][1], strlen($m[0][0]));
		}
	}

	return $form_data_html;
}

function csrfguard_inject() {
	echo csrfguard_inject_helper();
}

function csrfguard_inject_helper() {
	$data = ob_get_clean();
	$data = csrfguard_replace_forms($data);
	return $data;
}

function csrfguard_start() {
	if(count($_POST) && !isset($GLOBALS['CSRFGUARD_DISABLE'])) {
		if(!isset($_POST['CSRFName']) || !isset($_POST['CSRFToken'])) {
			die("Missing CSRF token.");
		}

		$name = $_POST['CSRFName'];
		$token = $_POST['CSRFToken'];
		if(!csrfguard_validate_token($name, $token)) {
			die("Invalid CSRF token.");
		}
	}

	ob_start();
	register_shutdown_function('csrfguard_inject');
}

csrfguard_start();

?>
