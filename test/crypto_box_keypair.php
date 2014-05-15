<?php

require "../TweetNaCl.php";

function printArr($arr) {
	for ($i = 0;$i < 32;++$i) {
		printf("0x%02x", $arr[$i]);
		if ($i < 31) printf(",");
		if ($i % 8 == 7) printf("\n");
	}
	printf("\n");
}

$secret = new SplFixedArray(32);
$public = new SplFixedArray(32);

$tweet = new TweetNaCl();

$tweet->crypto_box_keypair($public, $secret);

printf("secret key:\n");
printArr($secret);
printf("public key:\n");
printArr($public);
