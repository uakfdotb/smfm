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

//we assume each post and request element is a string
//this ensures that assumption is valid

foreach($_POST as $k => $v) {
	$_POST[$k] = print_r($v, true);
}

foreach($_REQUEST as $k => $v) {
	$_REQUEST[$k] = print_r($v, true);
}

?>
