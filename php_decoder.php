<?php
// developer @AxioReverse
// Usage: php php_decoder.php <inputPhpFile> <outputFile>

if ($argc !== 3) exit("Usage: php decoder.php <inputPhpFile> <outputFile>\n");
$inPath  = $argv[1];
$outPath = $argv[2];
if (!file_exists($inPath)) exit("Input file not found .\n");

$php = file_get_contents($inPath);
if ($php === false) exit("failed to read file\n");

function fail($msg){ exit("Decoding failed: $msg\n"); }

$src1 = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm9876543210-_*";
$dst  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
$src2 = "KLMNOPQRSTUVWXYZABCDEFGHIJklmnopqrstuvwxyzabcdefghij9876543210-_*";

function customDecode($data){
    global $src1,$dst;
    $mapped = strtr($data, $src1, $dst);
    $d = base64_decode($mapped, true);
    if ($d === false) fail("customDecode base64 decode failed.");
    return $d;
}
function doubleDecode($data){
    global $src2,$dst;
    $once = customDecode($data);
    $restored = strtr($once, $src2, $dst);
    $d = base64_decode($restored, true);
    if ($d === false) fail("doubleDecode base64 decode failed.");
    return $d;
}

$finalDataMap = [];
if (preg_match_all('/\$finalData_(\d+)\s*=\s*[\'"]([^\'"]*)[\'"]\s*;/', $php, $mm))
    for ($i=0;$i<count($mm[0]);$i++) $finalDataMap[intval($mm[1][$i])] = $mm[2][$i];
if (count($finalDataMap)===0) fail("No \$finalData_N variables found.");


if (!preg_match('/\$finalData_combined\s*=\s*([^;]+)\s*;/', $php, $cmb)) fail("Missing \$finalData_combined.");
if (!preg_match_all('/\$finalData_(\d+)/', $cmb[1], $m2)) fail("No variables in combined expression.");
$order = array_map('intval', $m2[1]);
$combinedStr = '';
foreach ($order as $idx){
    if (!isset($finalDataMap[$idx])) fail("Missing \$finalData_$idx reference.");
    $combinedStr .= $finalDataMap[$idx];
}

function extractDoubleArg($name,$php){
    $re = '/\$'.preg_quote($name,'/').'\s*=\s*base64_decode\s*\(\s*doubleDecode\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)\s*\)\s*;/i';
    return preg_match($re,$php,$m)?$m[1]:null;
}
$arg_key1=extractDoubleArg('key1',$php);
$arg_iv1=extractDoubleArg('iv1',$php);
$arg_key2=extractDoubleArg('key2',$php);
$arg_iv2=extractDoubleArg('iv2',$php);
if (!$arg_key1||!$arg_iv1||!$arg_key2||!$arg_iv2) fail("Failed to extract key/iv parameters.");

$key1_raw=doubleDecode($arg_key1);
$iv1_raw=doubleDecode($arg_iv1);
$key2_raw=doubleDecode($arg_key2);
$iv2_raw=doubleDecode($arg_iv2);
$encrypted=doubleDecode($combinedStr);

function try_b64($s){$d=base64_decode($s,true);return($d===false)?false:$d;}
$key1=$key1_raw; if(strlen($key1)!==32){$t=try_b64($key1_raw);if($t!==false&&strlen($t)===32)$key1=$t;}
$key2=$key2_raw; if(strlen($key2)!==32){$t=try_b64($key2_raw);if($t!==false&&strlen($t)===32)$key2=$t;}
$iv1=$iv1_raw;   if(strlen($iv1)!==16){$t=try_b64($iv1_raw);if($t!==false&&strlen($t)===16)$iv1=$t;}
$iv2=$iv2_raw;   if(strlen($iv2)!==16){$t=try_b64($iv2_raw);if($t!==false&&strlen($t)===16)$iv2=$t;}

if(strlen($key1)!==32) fail("Invalid key1 length.");
if(strlen($key2)!==32) fail("Invalid key2 length.");
if(strlen($iv1)!==16) fail("Invalid iv1 length.");
if(strlen($iv2)!==16) fail("Invalid iv2 length.");

$step1 = openssl_decrypt($encrypted, 'aes-256-cbc', $key2, OPENSSL_RAW_DATA, $iv2);
if($step1===false) fail("First AES decrypt failed.");

$step1 = strrev(str_rot13($step1));

$step2 = openssl_decrypt($step1, 'aes-256-cbc', $key1, OPENSSL_RAW_DATA, $iv1);
if($step2===false) fail("Second AES decrypt failed.");

$lastStar = strrpos($step2, '*');
if ($lastStar===false||strlen($step2)<=16) fail("Missing payload marker.");
$core = substr($step2, 16, $lastStar - 16);

$finalStage = str_rot13(strrev($core));
$c = preg_replace('/[^A-Za-z0-9+\/=]/','',$finalStage);
if ($c==='') fail("Invalid base64 content.");
$pad = strlen($c)%4;
if ($pad!==0) $c .= str_repeat('=',4-$pad);
$decoded = base64_decode($c, true);
if ($decoded === false) fail("Final base64 decode failed.");

// Write file
if (file_put_contents($outPath, $decoded) === false) fail("failed to write output file.");

echo "Decoding finished. Output saved to: $outPath\n";