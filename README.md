
# Fast Elliptic Curve Cryptography in PHP


## Information

This library is a PHP port of [elliptic](https://github.com/indutny/elliptic), a great JavaScript ECC library.

* Supported curve types: Short Weierstrass, Montgomery, Edwards, Twisted Edwards.
* Curve 'presets': `secp256k1`, `p192`, `p224`, `p256`, `p384`, `p521`, `curve25519`, `ed25519`.

This software is licensed under the MIT License.

Projects which use Fast ECC PHP library: [PrivMX WebMail](https://privmx.com), ...


## Benchmarks

```
+------------------------+----------------+--------+-----+------+
| subject                | mode           | rstdev | its | revs |
+------------------------+----------------+--------+-----+------+
| elliptic#genKeyPair    | 323.682ops/s   | 2.72%  | 5   | 50   |
| mdanter#genKeyPair     | 13.794ops/s    | 3.18%  | 5   | 50   |
+------------------------+----------------+--------+-----+------+
| elliptic#sign          | 307.228ops/s   | 3.82%  | 5   | 50   |
| mdanter#sign           | 14.118ops/s    | 2.12%  | 5   | 50   |
+------------------------+----------------+--------+-----+------+
| elliptic#verify        | 93.913ops/s    | 5.93%  | 5   | 50   |
| mdanter#verify         | 6.859ops/s     | 2.95%  | 5   | 50   |
+------------------------+----------------+--------+-----+------+
| elliptic#dh            | 135.166ops/s   | 1.67%  | 5   | 50   |
| mdanter#dh             | 14.302ops/s    | 0.89%  | 5   | 50   |
+------------------------+----------------+--------+-----+------+
| elliptic#EdDSASign     | 296.756ops/s   | 1.09%  | 5   | 50   |
+------------------------+----------------+--------+-----+------+
| elliptic#EdDSAVerify   | 67.481ops/s    | 2.76%  | 5   | 50   |
+------------------------+----------------+--------+-----+------+
```


## Installation

You can install this library via Composer:
```
composer require simplito/elliptic-php
```


## Implementation details

ECDSA is using deterministic `k` value generation as per [RFC6979][0]. Most of
the curve operations are performed on non-affine coordinates (either projective
or extended), various windowing techniques are used for different cases.

NOTE: `curve25519` could not be used for ECDSA, use `ed25519` instead.

All operations are performed in reduction context using [bn-php][1].


## API

### ECDSA

```php
<?php
use Elliptic\EC;

// Create and initialize EC context
// (better do it once and reuse it)
$ec = new EC('secp256k1');

// Generate keys
$key = $ec->genKeyPair();

// Sign message (can be hex sequence or array)
$msg = 'ab4c3451';
$signature = $key->sign($msg);

// Export DER encoded signature to hex string
$derSign = $signature->toDER('hex');

// Verify signature
echo "Verified: " . (($key->verify($msg, $derSign) == TRUE) ? "true" : "false") . "\n";

// CHECK WITH NO PRIVATE KEY

// Public key as '04 + x + y'
$pub = "049a1eedae838f2f8ad94597dc4368899ecc751342b464862da80c280d841875ab4607fb6ce14100e71dd7648dd6b417c7872a6ff1ff29195dabd99f15eff023e5";

// Signature MUST be either:
// 1) hex-string of DER-encoded signature; or
// 2) DER-encoded signature as byte array; or
// 3) object with two hex-string properties (r and s)

// case 1
$sig = '30450220233f8bab3f5df09e3d02f45914b0b519d2c04d13ac6964495623806a015df1cd022100c0c279c989b79885b3cc0f117643317bc59414bfb581f38e03557b8532f06603';

// case 2
$sig = [48,69,2,32,35,63,139,171,63,93,240,158,61,2,244,89,20,176,181,25,210,192,77,19,172,105,100,73,86,35,128,106,1,93,241,205,2,33,0,192,194,121,201,137,183,152,133,179,204,15,17,118,67,49,123,197,148,20,191,181,129,243,142,3,85,123,133,50,240,102,3];

// case 3
$sig = ['r' => '233f8bab3f5df09e3d02f45914b0b519d2c04d13ac6964495623806a015df1cd', 's' => 'c0c279c989b79885b3cc0f117643317bc59414bfb581f38e03557b8532f06603'];


// Import public key
$key = $ec->keyFromPublic($pub, 'hex');

// Verify signature
echo "Verified: " . (($key->verify($msg, $sig) == TRUE) ? "true" : "false") . "\n";
```

### EdDSA

```php
<?php
use Elliptic\EdDSA;

// Create and initialize EdDSA context
// (better do it once and reuse it)
$ec = new EdDSA('ed25519');

// Create key pair from secret
$key = $ec->keyFromSecret('61233ca4590acd'); // hex string or array of bytes

// Sign message (can be hex sequence or array)
$msg = 'ab4c3451';
$signature = $key->sign($msg)->toHex();

// Verify signature
echo "Verified: " . (($key->verify($msg, $signature) == TRUE) ? "true" : "false") . "\n";

// CHECK WITH NO PRIVATE KEY

// Import public key
$pub = '2763d01c334250d3e2dda459e5e3f949f667c6bbf0a35012c77ad40b00f0374d';
$key = $ec->keyFromPublic($pub, 'hex');

// Verify signature
$signature = '93899915C2919181A3D244AAAC032CE78EF76D2FFC0355D4BE2C70F48202EBC5F2BB0541D236182F55B11AC6346B524150695E5DE1FEA570786E1CC1F7999404';
echo "Verified: " . (($key->verify($msg, $signature) == TRUE) ? "true" : "false") . "\n";
```

### ECDH

```php
<?php
use Elliptic\EC;

$ec = new EC('curve25519');

// Generate keys
$key1 = $ec->genKeyPair();
$key2 = $ec->genKeyPair();

$shared1 = $key1->derive($key2->getPublic());
$shared2 = $key2->derive($key1->getPublic());

echo "Both shared secrets are BN instances\n";
echo $shared1->toString(16) . "\n";
echo $shared2->toString(16) . "\n";
```

NOTE: `.derive()` returns a [BN][1] instance. The resulting hex string is not zero-padded to constant size. Note that when interoperating with other libraries or using the result in a hash function.

### Using EC directly

Use case examples:

#### Computing public key from private 

```php
use Elliptic\EC;

$ec = new EC('secp256k1');

$priv_hex = "751ce088f64404e5889bf7e9e5c280b200b2dc158461e96b921df39a1dbc6635";
$pub_hex  = "03a319a1d10a91ada9a01ab121b81ae5f14580083a976e74945cdb014a4a52bae6";

$priv = $ec->keyFromPrivate($priv_hex);
if ($pub_hex == $priv->getPublic(true, "hex")) {
    echo "Success\n";
} else {
    echo "Fail\n";
}
```

#### Verifying Bitcoin Message Signature

```php
use Elliptic\EC;
use StephenHill\Base58;

// see: https://en.bitcoin.it/wiki/List_of_address_prefixes
const MainNetId = "\x00";
const TestNetId = "\x6F";
const PrefixNetIdMap = [ "1" => MainNetId, "m" => TestNetId ];

function pubKeyAddress($pubkey, $netid = MainNetId) {
    $b58 = new Base58();

    $pubenc   = hex2bin($pubkey->encode("hex", true));
    $pubhash  = $netid . hash('ripemd160', hash('sha256', $pubenc, true), true);
    $checksum = substr( hash('sha256', hash('sha256', $pubhash, true), true), 0, 4); 

    return $b58->encode($pubhash . $checksum);
}

function verifySignature($message, $signature, $address) {
    $signbin = base64_decode($signature);

    $signarr  = [ "r" => bin2hex(substr($signbin, 1, 32)), 
                  "s" => bin2hex(substr($signbin, 33, 32)) ];

    $nv = ord(substr($signbin, 0, 1)) - 27; 
    if ($nv != ($nv & 7)) 
        return false;

    $recid = ($nv & 3); 
    $compressed = ($nv & 4) != 0;

    $msglen = strlen($message);
    $hash = hash('sha256', hash('sha256', "\x18Bitcoin Signed Message:\n" . chr($msglen) . $message, true));

    $ec = new EC('secp256k1');
    $pub = $ec->recoverPubKey($hash, $signarr, $recid);

    $result = pubKeyAddress($pub, PrefixNetIdMap[$address[0]]);
    return $result == $address;
}

$message   = "I like signatures";
$signature = "H/zugYITIQTk8ZFWeXkbGCV2MzvMtbh+CnKBctbM9tP2UCb1B4LdyWFQuTZKxLdIDgP8Vsvl+0AEkBlY1HoyVw8=";
$address   = "mxQadqtYQXYeUsSqdMdJxZwkzxbd2tuMdc";

if (verifySignature($message, $signature, $address)) {
    echo "Success\n";
} else {
    echo "Fail\n";
}
``` 

#### Verifying Ethereum Signature

```php
use Elliptic\EC;
use kornrunner\Keccak;

function pubKeyToAddress($pubkey) {
    return "0x" . substr(Keccak::hash(substr(hex2bin($pubkey->encode("hex")), 1), 256), 24);
}

function verifySignature($message, $signature, $address) {
    $msglen = strlen($message);
    $hash   = Keccak::hash("\x19Ethereum Signed Message:\n{$msglen}{$message}", 256);
    $sign   = ["r" => substr($signature, 2, 64), 
               "s" => substr($signature, 66, 64)];
    $recid  = ord(hex2bin(substr($signature, 130, 2))) - 27; 
    if ($recid != ($recid & 1)) 
        return false;

    $ec = new EC('secp256k1');
    $pubkey = $ec->recoverPubKey($hash, $sign, $recid);

    return $address == pubKeyToAddress($pubkey);
}

$address   = "0x5a214a45585b336a776b62a3a61dbafd39f9fa2a";
$message   = "I like signatures";
// signature returned by eth.sign(address, message)
$signature = "0xacb175089543ac060ed48c3e25ada5ffeed6f008da9eaca3806e4acb707b9481401409ae1f5f9f290f54f29684e7bac1d79b2964e0edcb7f083bacd5fc48882e1b";

if (verifySignature($message, $signature, $address)) {
    echo "Success\n";
} else {
    echo "Fail\n";
}

```

#### ECDH (secret based, base58 format)

For usage in ed25519 oriented platforms like e.g. BigChainDB who use base58 encoded public / private keys.

```php
use Elliptic\EdDSA;
use StephenHill\Base58;

$mnemonic = "scheme spot photo card baby mountain device kick cradle pact join borrow";
$secret = hash_pbkdf2('sha512', $mnemonic, 'mnemonic', 2048);

$ec =  new EdDSA('ed25519');
$kp = $ec->keyFromSecret($secret);

assert($secret == $kp->getSecret('hex'));
echo "Secret:  " . $kp->getSecret('hex') . PHP_EOL;

echo "Private: " . $kp->priv()->toString('hex') . PHP_EOL;
echo "Public:  " . $kp->getPublic('hex') .  PHP_EOL;

$b58 = new Base58();
echo PHP_EOL;
echo "B58 Private: " . $b58->encode(hex2bin($kp->priv()->toString('hex'))) . PHP_EOL;
echo "B58 Public:  " . $b58->encode(hex2bin($kp->getPublic('hex'))) .  PHP_EOL;
```

#### BIP32 Public Parent Key -> Public Child Key derivation example

```php
<?php
use Elliptic\EC;
use BN\BN;

$ec = new EC('secp256k1');

// See: http://bip32.org using Derive From BIP32 Key
// xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8
$c_par = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
$K_par = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";

// Derived public child key 
// Derivation path Simple: m/i
// Keypair index i: 2018
// xpub68Gmy5EVb2Begkah8BxugKchT5SExW5p9gEHBLnEvYSuwVppt2TzD3WTjxNk14R8pmHbz3MHB9n75M2zNYgkJUCwV9pYwU9Z21Awj7Cr5U9
$expected_c_child = "a7470737ffde1458292e19e838534f400ad3c0f72e12f08eff79dee4fce11bed";
$expected_K_child = "0376499d06f9e9df71d7ee08d13a91337fa2b92182d4afcddf917b8d9983eb4615";

$i = 2018;
$I_key  = hex2bin($c_par);
$I_data = hex2bin($K_par) . pack("N", $i);
$I = hash_hmac("sha512", $I_data, $I_key);
$I_L = substr($I, 0, 64);
$I_R = substr($I, 64, 64);
$c_i = $I_R;

$K_par_point = $ec->curve->decodePoint($K_par, "hex");
$I_L_point = $ec->g->mul(new BN($I_L, 16));
$K_i = $K_par_point->add($I_L_point);
$K_i = $K_i->encodeCompressed("hex");

if ($expected_c_child == $c_i && $expected_K_child == $K_i) {
    echo "Success!\n";
} else {
    echo "Failure!\n";
}
```


[0]: http://tools.ietf.org/html/rfc6979
[1]: https://github.com/simplito/bn-php
