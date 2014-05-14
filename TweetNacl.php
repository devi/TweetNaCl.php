<?php
/**
 * TweetNaCl for PHP.
 *
 * 
 * Assembled from these sources:
 *  - http://tweetnacl.cr.yp.to/
 *  - https://github.com/agl/curve25519-donna
 *  - https://github.com/dchest/tweetnacl-js
 *  - https://github.com/chriskuehl/nacl.js
 *  - https://github.com/jedisct1/libsodium
 * 
 */
class TweetNaCl {

	/* XSalsa20 */

	function L32($x, $c) {
		return ($x << $c) | (($x&0xffffffff) >> (32 - $c));
	}

	function ld32($x, $xpos) {
		$u = $x[3+$xpos];
		$u = ($u<<8) | $x[2+$xpos];
		$u = ($u<<8) | $x[1+$xpos];
		return ($u<<8) | $x[0+$xpos];
	}

	function st32(&$x, $xpos, $u){
		for ($i = 0;$i < 4;++$i) {
			$x[$i+$xpos] = $u & 255;
			$u >>= 8;
		}
	}

	function core(&$out, $in, $k, $c, $h) {
		$w = new SplFixedArray(16);
		$x = new SplFixedArray(16);
		$y = new SplFixedArray(16);
		$t = new SplFixedArray(4);

		for ($i = 0;$i < 4;++$i) {
			$x[5*$i] = $this->ld32($c, 4*$i);
			$x[1+$i] = $this->ld32($k, 4*$i);
			$x[6+$i] = $this->ld32($in, 4*$i);
			$x[11+$i] = $this->ld32($k, 16+4*$i);
		}

		for ($i = 0;$i < 16;++$i) $y[$i] = $x[$i];

		for ($i = 0;$i < 20;++$i) {
			for ($j = 0;$j < 4;++$j) {
				for ($m = 0;$m < 4;++$m) $t[$m] = $x[(5*$j+4*$m)%16];
				$t[1] ^= $this->L32($t[0]+$t[3], 7);
				$t[1] &= 0xFFFFFFFF;
				$t[2] ^= $this->L32($t[1]+$t[0], 9);
				$t[2] &= 0xFFFFFFFF;
				$t[3] ^= $this->L32($t[2]+$t[1],13);
				$t[3] &= 0xFFFFFFFF;
				$t[0] ^= $this->L32($t[3]+$t[2],18);
				$t[0] &= 0xFFFFFFFF;
				for ($m = 0;$m < 4;++$m) $w[4*$j+($j+$m)%4] = $t[$m];
			}
			for ($m = 0;$m < 16;++$m) $x[$m] = $w[$m];
		}

		if ($h) {
			for ($i = 0;$i < 16;++$i) $x[$i] += $y[$i];
			for ($i = 0;$i < 4;++$i) {
				$x[5*$i] -= $this->ld32($c, 4*$i);
				$x[6+$i] -= $this->ld32($in, 4*$i);
			}
			for ($i = 0;$i < 4;++$i) {
				$this->st32($out, 4*$i, $x[5*$i]);
				$this->st32($out, 16+4*$i, $x[6+$i]);
			}
		} else {
			for ($i = 0;$i < 16;++$i) {
				$this->st32($out, 4 * $i, $x[$i] + $y[$i]);
			}
		}
	}

	function crypto_core_salsa20(&$out, $in, $k, $c) {
		$this->core($out, $in, $k, $c, 0);
		return 0;
	}

	function crypto_core_hsalsa20(&$out, $in, $k, $c) {
		$this->core($out, $in, $k, $c, 1);
		return 0;
	}

	static $sigma = array(101,120,112,97,110,100,32,51,50,45,98,121,116,101,32,107);

	function crypto_stream_salsa20_xor(&$c, $m, $b, $n, $k) {
		$z = new SplFixedArray(16);
		$x = new SplFixedArray(64);

		if (!$b) return 0;

		for ($i = 0;$i < 16;++$i) $z[$i] = 0;
		for ($i = 0;$i < 8;++$i) $z[$i] = $n[$i];

		$coffset = 0;
		$moffset = 0;
		while ($b >= 64) {
			$this->crypto_core_salsa20($x, $z, $k, static::$sigma);
			for ($i = 0;$i < 64;++$i) {
				$c[$i+$coffset] = ($m?$m[$i+$moffset]:0) ^ $x[$i];
			}
			$u = 1;
			for ($i = 8;$i < 16;++$i) {
				$u += $z[$i];
				$z[$i] = $u;
				$u >>= 8;
			}
			$b -= 64;
			$coffset += 64;
			if ($m) $moffset += 64;
		}
		if ($b) {
			$this->crypto_core_salsa20($x, $z, $k, static::$sigma);
			for ($i = 0;$i < $b;++$i) {
				$c[$i+$coffset] = ($m?$m[$i+$moffset]:0) ^ $x[$i];
			}
		}
		return 0;
	}

	function crypto_stream_salsa20(&$c, $d, $n, $k) {
		return $this->crypto_stream_salsa20_xor($c, 0, $d, $n, $k);
	}

	function crypto_stream(&$c, $d, $n, $k) {
		$s = new SplFixedArray(32);
		$subn = new SplFixedArray(16);
		$this->crypto_core_hsalsa20($s, $n, $k, static::$sigma);
		for ($i = 0;$i < 8;++$i) $subn[$i] = $n[$i+16];
		return $this->crypto_stream_salsa20($c, $d, $subn, $s);
	}

	function crypto_stream_xor(&$c, $m, $d, $n, $k) {
		$s = new SplFixedArray(32);
		$nrest = new SplFixedArray(8);
		$this->crypto_core_hsalsa20($s, $n, $k, static::$sigma);
		for ($i = 0;$i < 8;++$i) $nrest[$i] = $n[$i+16];
		return $this->crypto_stream_salsa20_xor($c, $m, $d, $nrest, $s);
	}

	/* Poly1305 */

	function vn($x, $y, $n, $xpos = 0, $ypos = 0) {
		$d = 0;
		for ($i = 0;$i < $n;++$i) $d |= $x[$i+$xpos] ^ $y[$i+$ypos];
		return (1 & (($d - 1) >> 8)) - 1;
	}

	function crypto_verify_16($x, $y, $xpos = 0, $ypos = 0) {
		return $this->vn($x, $y, 16, $xpos, $ypos);
	}

	function crypto_verify_32($x, $y, $xpos = 0, $ypos = 0) {
		return $this->vn($x, $y, 32, $xpos, $ypos);
	}

	function add1305(&$h, $c) {
		$u = 0;
		for ($j = 0;$j < 17;++$j) {
			$u += $h[$j] + $c[$j];
			$u &= 0xffffffff;
			$h[$j] = $u & 255;
			$u >>= 8;
		}
	}

	function crypto_onetimeauth(&$out, $m, $n, $k, $outpos = 0, $mpos = 0) {
		$x = new SplFixedArray(17);
		$r = new SplFixedArray(17);
		$h = new SplFixedArray(17);
		$c = new SplFixedArray(17);
		$g = new SplFixedArray(17);
		$minusp = array(5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252);

		for ($j = 0;$j < 16;++$j) $r[$j]=$k[$j];
		$r[3] &= 15;
		$r[4] &= 252;
		$r[7] &= 15;
		$r[8] &= 252;
		$r[11] &= 15;
		$r[12] &= 252;
		$r[15] &= 15;

		$s = $i = $j = $u = 0;
		while ($n > 0) {
			for ($j = 0;$j < 17;++$j) $c[$j] = 0;
			for ($j = 0;($j < 16) && ($j < $n);++$j) $c[$j] = $m[$j+$mpos];
			$c[$j] = 1;
			$mpos += $j; $n -= $j;
			$this->add1305($h,$c);
			for ($i = 0;$i < 17;++$i) {
				$x[$i] = 0;
				for ($j = 0;$j < 17;++$j) {
					$x[$i] += $h[$j] * (($j <= $i) ? $r[$i - $j] : 320 * $r[$i + 17 - $j]);
				}
			}
			for ($i = 0;$i < 17;++$i) $h[$i] = $x[$i];
			$u = 0;
			for ($j = 0;$j < 16;++$j) {
				$u += $h[$j];
				$h[$j] = $u & 255;
				$u >>= 8;
			}
			$u += $h[16]; $h[16] = $u & 3;
			$u = 5 * ($u >> 2);
			for ($j = 0;$j < 16;++$j) {
				$u += $h[$j];
				$h[$j] = $u & 255;
				$u >>= 8;
			}
			$u += $h[16]; $h[16] = $u;
		}
		for ($j = 0;$j < 17;++$j) $g[$j] = $h[$j];
		$this->add1305($h, $minusp);
		$s = -($h[16] >> 7);
		for ($j = 0;$j < 17;++$j) {
			$h[$j] ^= $s & ($g[$j] ^ $h[$j]);
			//$h[$j] &= 0xffffffff;
		}
		for ($j = 0;$j < 16;++$j) $c[$j] = $k[$j + 16];
		$c[16] = 0;
		$this->add1305($h, $c);
		for ($j = 0;$j < 16;++$j) $out[$j+$outpos] = $h[$j];
		return 0;
	}

	function crypto_onetimeauth_verify($h, $m, $n, $k, $hpos = 0, $mpos = 0) {
		$x = new SplFixedArray(16);
		$this->crypto_onetimeauth($x, $m, $n, $k, 0, $mpos);
		return $this->crypto_verify_16($h, $x, $hpos);
	}

	function crypto_secretbox(&$c, $m, $d, $n, $k) {
		if ($d < 32) return -1;
		$this->crypto_stream_xor($c, $m, $d, $n, $k);
		$this->crypto_onetimeauth($c, $c, $d - 32, $c, 16, 32);
		for ($i = 0;$i < 16;++$i) $c[$i] = 0;
		return 0;
	}

	function crypto_secretbox_open(&$m, $c, $d, $n, $k) {
		$x = new SplFixedArray(32);
		if ($d < 32) return -1;
		$this->crypto_stream($x, 32, $n, $k);
		if ($this->crypto_onetimeauth_verify($c, $c, $d - 32, $x, 16, 32) !== 0) return -1;
		$this->crypto_stream_xor($m, $c, $d, $n, $k);
		for ($i = 0;$i < 32;++$i) $m[$i] = 0;
		return 0;
	}

	/**
	 * Curve25519
	 * 
	 * Port of https://github.com/agl/curve25519-donna to PHP.
	 * 
	 * curve25519-donna is copyrighted by Google Inc.
	 */
	function feCopy($dst, $src, $offset) {
		for ($i = 0; $i < $offset; ++$i) $dst[$i] = $src[$i];
	}

	function fsum($output, $in) {
		for ($i = 0; $i < 10; $i += 2) {
			$output[0+$i] += $in[0+$i];
			$output[1+$i] += $in[1+$i];
		}
	}

	function fdifference($output, $in) {
		for ($i = 0; $i < 10; ++$i) {
			$output[$i] = ($in[$i] - $output[$i]);
		}
	}

	function fscalar_product($output, $in, $scalar) {
		for ($i = 0; $i < 10; ++$i) {
			$output[$i] = ($in[$i] * $scalar);
		}
	}

	function fproduct($output, $in2, $in) {
		$output[0] =    $in2[0] * $in[0];
		$output[1] =    $in2[0] * $in[1] +
						$in2[1] * $in[0];
		$output[2] =  2 *  $in2[1] * $in[1] +
						$in2[0] * $in[2] +
						$in2[2] * $in[0];
		$output[3] =    $in2[1] * $in[2] +
						$in2[2] * $in[1] +
						$in2[0] * $in[3] +
						$in2[3] * $in[0];
		$output[4] =    $in2[2] * $in[2] +
					 2 * ($in2[1] * $in[3] +
						$in2[3] * $in[1]) +
						$in2[0] * $in[4] +
						$in2[4] * $in[0];
		$output[5] =    $in2[2] * $in[3] +
						$in2[3] * $in[2] +
						$in2[1] * $in[4] +
						$in2[4] * $in[1] +
						$in2[0] * $in[5] +
						$in2[5] * $in[0];
		$output[6] =  2 * ($in2[3] * $in[3] +
						$in2[1] * $in[5] +
						$in2[5] * $in[1]) +
						$in2[2] * $in[4] +
						$in2[4] * $in[2] +
						$in2[0] * $in[6] +
						$in2[6] * $in[0];
		$output[7] =    $in2[3] * $in[4] +
						$in2[4] * $in[3] +
						$in2[2] * $in[5] +
						$in2[5] * $in[2] +
						$in2[1] * $in[6] +
						$in2[6] * $in[1] +
						$in2[0] * $in[7] +
						$in2[7] * $in[0];
		$output[8] =    $in2[4] * $in[4] +
					 2 * ($in2[3] * $in[5] +
						$in2[5] * $in[3] +
						$in2[1] * $in[7] +
						$in2[7] * $in[1]) +
						$in2[2] * $in[6] +
						$in2[6] * $in[2] +
						$in2[0] * $in[8] +
						$in2[8] * $in[0];
		$output[9] =    $in2[4] * $in[5] +
						$in2[5] * $in[4] +
						$in2[3] * $in[6] +
						$in2[6] * $in[3] +
						$in2[2] * $in[7] +
						$in2[7] * $in[2] +
						$in2[1] * $in[8] +
						$in2[8] * $in[1] +
						$in2[0] * $in[9] +
						$in2[9] * $in[0];
		$output[10] = 2 * ($in2[5] * $in[5] +
						$in2[3] * $in[7] +
						$in2[7] * $in[3] +
						$in2[1] * $in[9] +
						$in2[9] * $in[1]) +
						$in2[4] * $in[6] +
						$in2[6] * $in[4] +
						$in2[2] * $in[8] +
						$in2[8] * $in[2];
		$output[11] =   $in2[5] * $in[6] +
						$in2[6] * $in[5] +
						$in2[4] * $in[7] +
						$in2[7] * $in[4] +
						$in2[3] * $in[8] +
						$in2[8] * $in[3] +
						$in2[2] * $in[9] +
						$in2[9] * $in[2];
		$output[12] =   $in2[6] * $in[6] +
					 2 * ($in2[5] * $in[7] +
						$in2[7] * $in[5] +
						$in2[3] * $in[9] +
						$in2[9] * $in[3]) +
						$in2[4] * $in[8] +
						$in2[8] * $in[4];
		$output[13] =   $in2[6] * $in[7] +
						$in2[7] * $in[6] +
						$in2[5] * $in[8] +
						$in2[8] * $in[5] +
						$in2[4] * $in[9] +
						$in2[9] * $in[4];
		$output[14] = 2 * ($in2[7] * $in[7] +
						$in2[5] * $in[9] +
						$in2[9] * $in[5]) +
						$in2[6] * $in[8] +
						$in2[8] * $in[6];
		$output[15] =   $in2[7] * $in[8] +
						$in2[8] * $in[7] +
						$in2[6] * $in[9] +
						$in2[9] * $in[6];
		$output[16] =   $in2[8] * $in[8] +
					 2 * ($in2[7] * $in[9] +
						$in2[9] * $in[7]);
		$output[17] =   $in2[8] * $in[9] +
						$in2[9] * $in[8];
		$output[18] = 2 *  $in2[9] * $in[9];
	}

	function freduce_degree($output) {
		$output[8] += $output[18] << 4;
		$output[8] += $output[18] << 1;
		$output[8] += $output[18];
		$output[7] += $output[17] << 4;
		$output[7] += $output[17] << 1;
		$output[7] += $output[17];
		$output[6] += $output[16] << 4;
		$output[6] += $output[16] << 1;
		$output[6] += $output[16];
		$output[5] += $output[15] << 4;
		$output[5] += $output[15] << 1;
		$output[5] += $output[15];
		$output[4] += $output[14] << 4;
		$output[4] += $output[14] << 1;
		$output[4] += $output[14];
		$output[3] += $output[13] << 4;
		$output[3] += $output[13] << 1;
		$output[3] += $output[13];
		$output[2] += $output[12] << 4;
		$output[2] += $output[12] << 1;
		$output[2] += $output[12];
		$output[1] += $output[11] << 4;
		$output[1] += $output[11] << 1;
		$output[1] += $output[11];
		$output[0] += $output[10] << 4;
		$output[0] += $output[10] << 1;
		$output[0] += $output[10];
	}

	function div_by_2_26($v) {
		$highword = $v >> 32;
		$sign = $highword >> 31;
		$roundoff = $sign >> 6;
		return ($v + $roundoff) >> 26;
	}

	function div_by_2_25($v) {
		$highword = $v > 32;
		$sign = $highword >> 31;
		$roundoff = $sign >> 7;
		return ($v + $roundoff) >> 25;
	}

	function div_s32_by_2_25($v) {
		$roundoff = ($v >> 31) >> 7;
		return ($v + $roundoff) >> 25;
	}

	function freduce_coefficients($output) {
		$output[10] = 0;

		for ($i = 0; $i < 10; $i += 2) {
			$over = $this->div_by_2_26($output[$i]);
			$output[$i] -= $over << 26;
			$output[$i+1] += $over;
			$over = $this->div_by_2_25($output[$i+1]);
			$output[$i+1] -= $over << 25;
			$output[$i+2] += $over;
		}

		$output[0] += $output[10] << 4;
		$output[0] += $output[10] << 1;
		$output[0] += $output[10];

		$output[10] = 0;

		$over = $this->div_by_2_26($output[0]);
		$output[0] -= $over << 26;
		$output[1] += $over;

		$over32 = $this->div_s32_by_2_25($output[1]);
		$output[1] -= $over32 << 25;
		$output[2] += $over32;
	}

	function fmul($output, $in, $in2) {
		$t = new SplFixedArray(19);
		$this->fproduct($t, $in, $in2);
		$this->freduce_degree($t);
		$this->freduce_coefficients($t);
		$this->feCopy($output, $t, 10);
	}

	function fsquare_inner($output, $in) {
		$output[0] =       $in[0] * $in[0];
		$output[1] =  2 *  $in[0] * $in[1];
		$output[2] =  2 * ($in[1] * $in[1] +
							 $in[0] * $in[2]);
		$output[3] =  2 * ($in[1] * $in[2] +
							 $in[0] * $in[3]);
		$output[4] =       $in[2] * $in[2] +
						4 *  $in[1] * $in[3] +
						2 *  $in[0] * $in[4];
		$output[5] =  2 * ($in[2] * $in[3] +
							 $in[1] * $in[4] +
							 $in[0] * $in[5]);
		$output[6] =  2 * ($in[3] * $in[3] +
							 $in[2] * $in[4] +
							 $in[0] * $in[6] +
						2 *  $in[1] * $in[5]);
		$output[7] =  2 * ($in[3] * $in[4] +
							 $in[2] * $in[5] +
							 $in[1] * $in[6] +
							 $in[0] * $in[7]);
		$output[8] =       $in[4] * $in[4] +
						2 * ($in[2] * $in[6] +
							 $in[0] * $in[8] +
						2 * ($in[1] * $in[7] +
							 $in[3] * $in[5]));
		$output[9] =  2 * ($in[4] * $in[5] +
							 $in[3] * $in[6] +
							 $in[2] * $in[7] +
							 $in[1] * $in[8] +
							 $in[0] * $in[9]);
		$output[10] = 2 * ($in[5] * $in[5] +
							 $in[4] * $in[6] +
							 $in[2] * $in[8] +
						2 * ($in[3] * $in[7] +
							 $in[1] * $in[9]));
		$output[11] = 2 * ($in[5] * $in[6] +
							 $in[4] * $in[7] +
							 $in[3] * $in[8] +
							 $in[2] * $in[9]);
		$output[12] =      $in[6] * $in[6] +
						2 * ($in[4] * $in[8] +
						2 * ($in[5] * $in[7] +
							 $in[3] * $in[9]));
		$output[13] = 2 * ($in[6] * $in[7] +
							 $in[5] * $in[8] +
							 $in[4] * $in[9]);
		$output[14] = 2 * ($in[7] * $in[7] +
							 $in[6] * $in[8] +
						2 *  $in[5] * $in[9]);
		$output[15] = 2 * ($in[7] * $in[8] +
							 $in[6] * $in[9]);
		$output[16] =      $in[8] * $in[8] +
						4 *  $in[7] * $in[9];
		$output[17] = 2 *  $in[8] * $in[9];
		$output[18] = 2 *  $in[9] * $in[9];
	}

	function fsquare($output, $in) {
		$t = new SplFixedArray(19);
		$this->fsquare_inner($t, $in);
		$this->freduce_degree($t);
		$this->freduce_coefficients($t);
		$this->feCopy($output, $t, 10);
	}

	function load_element($out, $in, $offset, $start, $shift, $mask) {
		$out[$offset] = ((
				$in[$start+0] |
				$in[$start+1] << 8 |
				$in[$start+2] << 16 |
				$in[$start+3] << 24) >> $shift) & $mask;
	}

	function fexpand($output, $input) {
		$this->load_element($output, $input, 0, 0, 0, 0x3ffffff);
		$this->load_element($output, $input, 1, 3, 2, 0x1ffffff);
		$this->load_element($output, $input, 2, 6, 3, 0x3ffffff);
		$this->load_element($output, $input, 3, 9, 5, 0x1ffffff);
		$this->load_element($output, $input, 4, 12, 6, 0x3ffffff);
		$this->load_element($output, $input, 5, 16, 0, 0x1ffffff);
		$this->load_element($output, $input, 6, 19, 1, 0x3ffffff);
		$this->load_element($output, $input, 7, 22, 3, 0x1ffffff);
		$this->load_element($output, $input, 8, 25, 4, 0x3ffffff);
		$this->load_element($output, $input, 9, 28, 6, 0x3ffffff);
	}

	function store_element($out, $in, $i, $s) {
		$out[$s+0] |= $in[$i] & 0xff;
		$out[$s+1] = ($in[$i] >> 8) & 0xff;
		$out[$s+2] = ($in[$i] >> 16) & 0xff;
		$out[$s+3] = ($in[$i] >> 24) & 0xff;
	}

	function fcontract($output, $input) {
		for ($j = 0; $j < 2; ++$j) {
			for ($i = 0; $i < 9; ++$i) {
				if (($i & 1) === 1) {
					$mask = $input[$i] >> 31;
					$carry = -(($input[$i] & $mask) >> 25);
					$input[$i] += $carry << 25;
					$input[$i+1] -= $carry;
				} else {
					$mask = $input[$i] >> 31;
					$carry = -(($input[$i] & $mask) >> 26);
					$input[$i] += $carry << 26;
					$input[$i+1] -= $carry;
				}
			}
			$mask = $input[9] >> 31;
			$carry = -(($input[9] & $mask) >> 25);
			$input[9] += $carry << 25;
			$input[0] -= $carry * 19;
		}

		$mask = $input[0] >> 31;
		$carry = -(($input[0] & $mask) >> 26);
		$input[0] += $carry << 26;
		$input[1] -= $carry;

		$input[1] <<= 2;
		$input[2] <<= 3;
		$input[3] <<= 5;
		$input[4] <<= 6;
		$input[6] <<= 1;
		$input[7] <<= 3;
		$input[8] <<= 4;
		$input[9] <<= 6;

		$output[0] = 0;
		$output[16] = 0;

		$this->store_element($output, $input, 0,0);
		$this->store_element($output, $input, 1,3);
		$this->store_element($output, $input, 2,6);
		$this->store_element($output, $input, 3,9);
		$this->store_element($output, $input, 4,12);
		$this->store_element($output, $input, 5,16);
		$this->store_element($output, $input, 6,19);
		$this->store_element($output, $input, 7,22);
		$this->store_element($output, $input, 8,25);
		$this->store_element($output, $input, 9,28);
	}

	function fmonty($x2, $z2,
					$x3, $z3,
					$x, $z,
					$xprime, $zprime,
					$qmqp) {
		$origx = new SplFixedArray(10);
		$origxprime = new SplFixedArray(10);
		$zzz = new SplFixedArray(19);
		$xx = new SplFixedArray(19);
		$zz = new SplFixedArray(19);
		$xxprime = new SplFixedArray(19);
		$zzprime = new SplFixedArray(19);
		$zzzprime = new SplFixedArray(19);
		$xxxprime = new SplFixedArray(19);

		$this->feCopy($origx, $x, 10);
		$this->fsum($x, $z);
		$this->fdifference($z, $origx);
		$this->feCopy($origxprime, $xprime, 10);
		$this->fsum($xprime, $zprime);
		$this->fdifference($zprime, $origxprime);
		$this->fproduct($xxprime, $xprime, $z);
		$this->fproduct($zzprime, $x, $zprime);
		$this->freduce_degree($xxprime);
		$this->freduce_coefficients($xxprime);
		$this->freduce_degree($zzprime);
		$this->freduce_coefficients($zzprime);
		$this->feCopy($origxprime, $xxprime, 10);
		$this->fsum($xxprime, $zzprime);
		$this->fdifference($zzprime, $origxprime);
		$this->fsquare($xxxprime, $xxprime);
		$this->fsquare($zzzprime, $zzprime);
		$this->fproduct($zzprime, $zzzprime, $qmqp);
		$this->freduce_degree($zzprime);
		$this->freduce_coefficients($zzprime);
		$this->feCopy($x3, $xxxprime, 10);
		$this->feCopy($z3, $zzprime, 10);
		$this->fsquare($xx, $x);
		$this->fsquare($zz, $z);
		$this->fproduct($x2, $xx, $zz);
		$this->freduce_degree($x2);
		$this->freduce_coefficients($x2);
		$this->fdifference($zz, $xx);
		$this->fscalar_product($zzz, $zz, 121665);
		$this->freduce_coefficients($zzz);
		$this->fsum($zzz, $xx);
		$this->fproduct($z2, $zz, $zzz);
		$this->freduce_degree($z2);
		$this->freduce_coefficients($z2);
	}

	function swap_conditional($a, $b, $iswap) {
		$swap = -$iswap;
		for ($i = 0; $i < 10; ++$i) {
			$x = $swap & ($a[$i] ^ $b[$i]);
			$a[$i] = $a[$i] ^ $x;
			$b[$i] = $b[$i] ^ $x;
		}
	}

	function cmult($resultx, $resultz, $n, $q) {
		$a = new SplFixedArray(19);
		$b = new SplFixedArray(19); $b[0] = 1;
		$c = new SplFixedArray(19); $c[0] = 1;
		$d = new SplFixedArray(19);
		$nqpqx = $a;
		$nqpqz = $b;
		$nqx = $c;
		$nqz = $d;
		$t = new SplFixedArray(19);
		$e = new SplFixedArray(19);
		$f = new SplFixedArray(19); $f[0] = 1;
		$g = new SplFixedArray(19);
		$h = new SplFixedArray(19); $h[0] = 1;
		$nqpqx2 = $e;
		$nqpqz2 = $f;
		$nqx2 = $g;
		$nqz2 = $h;

		$this->feCopy($nqpqx, $q, 10);

		for ($i = 0; $i < 32; ++$i) {
			$byte = $n[31 - $i];
			for ($j = 0; $j < 8; ++$j) {
				$bit = $byte >> 7;
				$bit &= 1;

				$this->swap_conditional($nqx, $nqpqx, $bit);
				$this->swap_conditional($nqz, $nqpqz, $bit);
				$this->fmonty($nqx2, $nqz2,
					$nqpqx2, $nqpqz2,
					$nqx, $nqz,
					$nqpqx, $nqpqz,
					$q);
				$this->swap_conditional($nqx2, $nqpqx2, $bit);
				$this->swap_conditional($nqz2, $nqpqz2, $bit);

				$t = $nqx;
				$nqx = $nqx2;
				$nqx2 = $t;
				$t = $nqz;
				$nqz = $nqz2;
				$nqz2 = $t;
				$t = $nqpqx;
				$nqpqx = $nqpqx2;
				$nqpqx2 = $t;
				$t = $nqpqz;
				$nqpqz = $nqpqz2;
				$nqpqz2 = $t;

				$byte <<= 1;
			}
		}

		$this->feCopy($resultx, $nqx, 10);
		$this->feCopy($resultz, $nqz, 10);
	}

	function crecip($out, $z) {
		$z2 = new SplFixedArray(10);
		$z9 = new SplFixedArray(10);
		$z11 = new SplFixedArray(10);
		$z2_5_0 = new SplFixedArray(10);
		$z2_10_0 = new SplFixedArray(10);
		$z2_20_0 = new SplFixedArray(10);
		$z2_50_0 = new SplFixedArray(10);
		$z2_100_0 = new SplFixedArray(10);
		$t0 = new SplFixedArray(10);
		$t1 = new SplFixedArray(10);

		$this->fsquare($z2,$z);
		$this->fsquare($t1,$z2);
		$this->fsquare($t0,$t1);
		$this->fmul($z9,$t0,$z);
		$this->fmul($z11,$z9,$z2);
		$this->fsquare($t0,$z11);
		$this->fmul($z2_5_0,$t0,$z9);

		$this->fsquare($t0,$z2_5_0);
		$this->fsquare($t1,$t0);
		$this->fsquare($t0,$t1);
		$this->fsquare($t1,$t0);
		$this->fsquare($t0,$t1);
		$this->fmul($z2_10_0,$t0,$z2_5_0);

		$this->fsquare($t0,$z2_10_0);
		$this->fsquare($t1,$t0);
		for ($i = 2;$i < 10;$i += 2) {
			$this->fsquare($t0,$t1);
			$this->fsquare($t1,$t0);
		}
		$this->fmul($z2_20_0,$t1,$z2_10_0);

		$this->fsquare($t0,$z2_20_0);
		$this->fsquare($t1,$t0);
		for ($i = 2;$i < 20;$i += 2) {
			$this->fsquare($t0,$t1);
			$this->fsquare($t1,$t0);
		}
		$this->fmul($t0,$t1,$z2_20_0);

		$this->fsquare($t1,$t0);
		$this->fsquare($t0,$t1);
		for ($i = 2;$i < 10;$i += 2) {
			$this->fsquare($t1,$t0);
			$this->fsquare($t0,$t1);
		}
		$this->fmul($z2_50_0,$t0,$z2_10_0);

		$this->fsquare($t0,$z2_50_0);
		$this->fsquare($t1,$t0);
		for ($i = 2;$i < 50;$i += 2) {
			$this->fsquare($t0,$t1);
			$this->fsquare($t1,$t0);
		}
		$this->fmul($z2_100_0,$t1,$z2_50_0);

		$this->fsquare($t1,$z2_100_0);
		$this->fsquare($t0,$t1);
		for ($i = 2;$i < 100;$i += 2) {
			$this->fsquare($t1,$t0);
			$this->fsquare($t0,$t1);
		}
		$this->fmul($t1,$t0,$z2_100_0);

		$this->fsquare($t0,$t1);
		$this->fsquare($t1,$t0);
		for ($i = 2;$i < 50;$i += 2) {
			$this->fsquare($t0,$t1);
			$this->fsquare($t1,$t0);
		}
		$this->fmul($t0,$t1,$z2_50_0);

		$this->fsquare($t1,$t0);
		$this->fsquare($t0,$t1);
		$this->fsquare($t1,$t0);
		$this->fsquare($t0,$t1);
		$this->fsquare($t1,$t0);
		$this->fmul($out,$t1,$z11);
	}

	function crypto_scalarmult($output, $secret, $base) {
		$bp = new SplFixedArray(10);
		$x = new SplFixedArray(10);
		$z = new SplFixedArray(11);
		$zmone = new SplFixedArray(10);
		$e = new SplFixedArray(32);

		for ($i = 0; $i < 32; ++$i) $e[$i] = $secret[$i];
		$e[0] &= 248;
		$e[31] &= 127;
		$e[31] |= 64;

		$this->fexpand($bp, $base);
		$this->cmult($x, $z, $e, $bp);
		$this->crecip($zmone, $z);
		$this->fmul($z, $x, $zmone);
		$this->freduce_coefficients($z);
		$this->fcontract($output, $z);
	}

	function crypto_scalarmult_base($output, $secret) {
		$base = new SplFixedArray(32);
		$base[0] = 9;
		$this->crypto_scalarmult($output, $secret, $base);
	}

	function randombytes(&$out, $len) {
		$x = 0;
		// shameless copy from phpseclib BigInteger
		// see for details: https://github.com/phpseclib/phpseclib
		if (file_exists('/dev/urandom') && is_readable('/dev/urandom')) {
			static $fp = true;
			if ($fp === true) {
				// warning's will be output unles the error suppression operator is used. errors such as
				// "open_basedir restriction in effect", "Permission denied", "No such file or directory", etc.
				$fp = @fopen('/dev/urandom', 'rb');
			}
			if ($fp !== true && $fp !== false) { // surprisingly faster than !is_bool() or is_resource()
				$x = fread($fp, $len);
			}
		} else if (function_exists('mcrypt_create_iv')) {
			$x = mcrypt_create_iv($len, MCRYPT_DEV_URANDOM);
		} else if (function_exists('openssl_random_pseudo_bytes')) {
			$x = openssl_random_pseudo_bytes($len);
		}
		if ($x) for ($i = 0;$i < $len; ++$i) $out[$i] = ord($x[$i]);
	}

	/* Crypto Box */

	function crypto_box_keypair($public, &$secret) {
		$this->randombytes($secret, 32);
		if (count($secret) !== 32 || count($public) !== 32) return -1;
		$this->crypto_scalarmult_base($public, $secret);
		return 0;
	}

	function crypto_box_beforenm(&$k, $y, $x) {
		$s = new SplFixedArray(32);
		$zero = new SplFixedArray(16);
		for ($i = 0;$i < 16;++$i) $zero[$i] = 0;
		$this->crypto_scalarmult($s, $x, $y);
		return $this->crypto_core_hsalsa20($k, $zero, $s, static::$sigma);
	}

	function crypto_box_afternm(&$c, $m, $d, $n, $k) {
		return $this->crypto_secretbox($c, $m, $d, $n, $k);
	}

	function crypto_box_open_afternm(&$m, $c, $d, $n, $k) {
		return $this->crypto_secretbox_open($m, $c, $d, $n, $k);
	}

	function crypto_box(&$c, $m, $d, $n, $y, $x) {
		$k = new SplFixedArray(32);
		$this->crypto_box_beforenm($k, $y, $x);
		return $this->crypto_box_afternm($c, $m, $d, $n, $k);
	}

	function crypto_box_open(&$m, $c, $d, $n, $y, $x) {
		$k = new SplFixedArray(32);
		$this->crypto_box_beforenm($k, $y, $x);
		return $this->crypto_box_open_afternm($m, $c, $d, $n, $k);
	}

}
