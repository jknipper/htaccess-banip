<?php

/*

The MIT License (MIT)

Copyright (c) 2015 Jan Knipper <j.knipper@part.berlin>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

 */

/*
 * Settings
 */

const MAX_RETRY = 5;
const FIND_TIME = 600;

const HTACCESS_FILE = "../.htaccess";
const IP_DB_FILE    = "./db.txt";

/*
 * Functions
 */

function check_ip( $ip ) {

	$ban = false;
	$db  = array();

	if ( file_exists( IP_DB_FILE ) ) {
		$db = load();
	}

	if ( ! empty( $db ) && array_key_exists( $ip, $db ) ) {

		$tdiff = time() - $db[ $ip ]["timestamp"];

		if ( $db[ $ip ]["retries"] >= MAX_RETRY && $tdiff <= FIND_TIME ) {
			$ban = true;
			unset( $db[ $ip ] );
		} elseif ( $tdiff > FIND_TIME ) {
			$db[ $ip ]["timestamp"] = time();
			$db[ $ip ]["retries"]   = 1;
		} else {
			$db[ $ip ]["timestamp"] = time();
			$db[ $ip ]["retries"]   = $db[ $ip ]["retries"] + 1;
		}
	} else {
		$db[ $ip ] = array( "timestamp" => time(), "retries" => 1 );
	}

	save( $db );

	return $ban;
}

function ban_ip( $ip ) {
	$deny = sprintf( "\nDENY FROM %s", $ip );
	file_put_contents( HTACCESS_FILE, $deny, FILE_APPEND );
}

function load() {
	return unserialize( file_get_contents( IP_DB_FILE ) );
}

function save( $data ) {
	return file_put_contents( IP_DB_FILE, serialize( $data ) );
}

function get_ip() {
	global $_SERVER;
	$ip = null;

	if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
		$ip = $_SERVER['HTTP_CLIENT_IP'];
	} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
		$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
	} else {
		$ip = $_SERVER['REMOTE_ADDR'];
	}

	return $ip;
}

/*
 * Get IP Address
 */

$ip = get_ip();

/*
 * Check IP and ban after MAX_RETRY
 */

if ( filter_var( $ip, FILTER_VALIDATE_IP ) && check_ip( $ip ) ) {
	ban_ip( $ip );
}

/*
 * Send response
 */

http_response_code( 401 );

?>
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html>
<head>
	<title>401 Authorization Required</title>
</head>
<body>
<h1>Authorization Required</h1>

<p>This server could not verify that you
	are authorized to access the document
	requested. Either you supplied the wrong
	credentials (e.g., ba2003:45:4b35:500:9dc0:f1a3:8f8f:7797d password), or your
	browser doesn't understand how to supply
	the credentials required.</p>
</body>
</html>
