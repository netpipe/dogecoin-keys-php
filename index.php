<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

define('SECP256K1_CURVE_ORDER', 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
define('SECP256K1_GX', '79BE667EF9DCBBAC55A62B64ED3B62CBB39A562B8F1B9B29E55A62B64ED3B62C');
define('SECP256K1_GY', '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A953F1BC61D1E510C6B5AA2');
define('SECP256K1_P', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');

function generatePrivateKey() {
    return bin2hex(random_bytes(32));
}

function hexToGmp($hex) {
    return gmp_init($hex, 16);
}

// Convert a GMP resource back to a hex string
function gmpToHex($gmp) {
    return gmp_strval($gmp, 16);
}

// Convert a hex string to binary
function hex2bin3($hex) {
    return pack('H*', $hex);
}

// Convert binary to base58 (Base58Check encoding for Dogecoin address)
function base58_encode($data) {
    $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    $base58 = '';
    $hex = bin2hex($data);
    $value = gmp_init('0x' . $hex, 16);

    while (gmp_cmp($value, gmp_init(58)) >= 0) {
        $mod = gmp_mod($value, 58);
        $value = gmp_div($value, 58);
        $base58 = $alphabet[gmp_intval($mod)] . $base58;
    }

    $base58 = $alphabet[gmp_intval($value)] . $base58;

    return $base58;
}
// RIPEMD160 hash function (can be replaced by an existing PHP extension)
function ripemd160($data) {
    return hash('ripemd160', $data, true);
}

function publicKeyToAddress($publicKey) {
    echo "Generating address from public key: $publicKey\n";
    $sha256 = hash('sha256', hex2bin($publicKey));
    $ripemd160 = ripemd160(hex2bin($sha256));

    $versioned = '1E' . bin2hex($ripemd160);
    $checksum = hash('sha256', hex2bin($versioned));
    $checksum = hash('sha256', hex2bin($checksum));
    $checksum = substr($checksum, 0, 8);

    $address = $versioned . $checksum;

    echo "Base58 address: $address\n";
    return base58_encode(hex2bin($address));
}

function privateKeyToPublicKey($privateKey) {
    echo "Generating public key from private key...\n";
    $privateKeyGmp = hexToGmp($privateKey);
    $x = hexToGmp(SECP256K1_GX);
    $y = hexToGmp(SECP256K1_GY);
    $order = hexToGmp(SECP256K1_CURVE_ORDER);

    $publicKeyX = gmp_mul($privateKeyGmp, $x);
    $publicKeyY = gmp_mul($privateKeyGmp, $y);

    $publicKeyX = gmp_mod($publicKeyX, $order);
    $publicKeyY = gmp_mod($publicKeyY, $order);

    return gmpToHex($publicKeyX) . gmpToHex($publicKeyY);
}

function generateDogecoinKeypair() {
    echo "Starting keypair generation...\n";
    $privateKey = generatePrivateKey();
    echo "Private key: $privateKey\n";

    $publicKey = privateKeyToPublicKey($privateKey);
    echo "Public key: $publicKey\n";

    $address = publicKeyToAddress($publicKey);
    echo "Generated Dogecoin Address: $address\n";

    return [
        'private_key' => $privateKey,
        'public_key' => $publicKey,
        'address' => $address
    ];
}

echo "Starting the process...\n";
$keypair = generateDogecoinKeypair();
echo "Keypair generation complete.\n";
?>