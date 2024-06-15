<?php

header("Content-type: application/json;");

// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

function getRandomName()
{
    $alphabet = "abcdefghijklmnopqrstuvwxyz";
    $name = "";
    for ($i = 0; $i < 10; $i++) {
        // Get a random letter from the alphabet
        $randomLetter = $alphabet[rand(0, strlen($alphabet) - 1)];
        // Add the letter to the name string
        $name .= $randomLetter;
    }
    return $name;
}

function isValidIpOrDomain($input)
{
    if (filter_var($input, FILTER_VALIDATE_IP)) {
        return true;
    } elseif (
        filter_var($input, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
    ) {
        return true;
    } else {
        return false;
    }
}

function changeEqualwith3D($input)
{
    return str_replace("=", "%3D", $input);
}

function decimalToBase64($decimalString)
{
    $decimals = explode(",", $decimalString);
    $bytes = array_map("chr", $decimals);
    $binaryString = implode("", $bytes);
    $base64String = base64_encode($binaryString);
    return $base64String;
}

function base64ToDecimal($base64String)
{
    $binaryString = base64_decode($base64String);
    $bytes = str_split($binaryString);
    $decimals = array_map("ord", $bytes);
    $decimalString = implode(",", $decimals);
    return $decimalString;
}

function getRandomIp ($ipRange) {
    $ipArray = explode(".", $ipRange);
    $randNum = rand(0,255);
    unset($ipArray[3]);
    return implode(".", $ipArray) . "." . strval($randNum);
}

$ipRanges = [
    "162.159.192.0",
    "162.159.193.0",
    "162.159.195.0",
    "188.114.96.0",
    "188.114.97.0",
    "188.114.98.0",
    "188.114.99.0"
];

$choosenRange = $ipRanges[rand(0,6)];
$choosenIp = getRandomIp($choosenRange);

$ports = "500,854,859,864,878,880,890,891,894,903,908,928,934,939,942,943,945,946,955,968,987,988,1002,1010,1014,1018,1070,1074,1180,1387,1701,1843,2371,2408,2506,3138,3476,3581,384,4177,4198,4233,4500,5279,5956,7103,7152,7156,7281,7559,8319,8742,8854,8886";
$portsArray = explode(",", $ports);
$choosenPort = $portsArray[array_rand($portsArray)];

function createWarp($ip = "", $port = "")
{
    $result_output = shell_exec("./warp-api");

    // Extract the device_id, private_key, and warp_token from the output using awk
    preg_match("/device_id: (.*)/", $result_output, $device_id_match);
    preg_match("/private_key: (.*)/", $result_output, $private_key_match);
    preg_match("/token: (.*)/", $result_output, $warp_token_match);

    $device_id = $device_id_match[1];
    $private_key = $private_key_match[1];
    $warp_token = $warp_token_match[1];

    // Generate the warp.conf file contents
    $warp_conf = "[Account]\n";
    $warp_conf .= "Device = $device_id\n";
    $warp_conf .= "PrivateKey = $private_key\n";
    $warp_conf .= "Token = $warp_token\n";
    $warp_conf .= "Type = free\n";
    $warp_conf .= "Name = WARP\n";
    $warp_conf .= "MTU = 1280\n\n";
    $warp_conf .= "[Peer]\n";
    $warp_conf .= "PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n";
    $warp_conf .= "Endpoint = 162.159.192.8:0\n";
    $warp_conf .= "Endpoint6 = [2606:4700:d0::a29f:c008]:0\n";
    $warp_conf .= "# AllowedIPs = 0.0.0.0/0\n";
    $warp_conf .= "# AllowedIPs = ::/0\n";
    $warp_conf .= "KeepAlive = 30\n";

    // Write the warp.conf file
    file_put_contents("warp.conf", $warp_conf);
    $warpPlusKey = generateWarpPlusKey();

    if (!is_null($warpPlusKey)) {
        if (is_null($device_name)) {
            $device_name = getRandomName();
        }
        // Run the warp-go command with the generated warp.conf file
        shell_exec(
            "./warp-go --update --config=./warp.conf --license=$warpkey --device-name=$device_name"
        );
    }

    $warp = shell_exec(
        "./warp-go --config=warp.conf --export-singbox=proxy.json"
    );
    $tempOutbound = json_decode(file_get_contents("proxy.json"), true)[
        "outbounds"
    ][0];

    $reserved = implode(",", $tempOutbound["reserved"]);
    if (isValidIpOrDomain($ip) && $port !== "") {
        $tempOutbound["server"] = $ip;
        $tempOutbound["server_port"] = intval($port);
    } else {
        $ip = $tempOutbound["server"];
        $port = $tempOutbound["server_port"];
    }
    $private_key = changeEqualwith3D($tempOutbound["private_key"]);
    $public_key = changeEqualwith3D($tempOutbound["peer_public_key"]);
    $hash = getRandomName();
    
    $baseStreisand = "wireguard://{$ip}:{$port}?private_key={$private_key}&peer_public_key={$public_key}&mtu=1280&reserved={$reserved}#{$hash}";
    $baseHiddify =
        "wg://{$ip}:{$port}/?pk={$private_key}&peer_public_key={$public_key}&local_address=172.16.0.2/24,2606:4700:110:835b:afd4:b62b:a64a:2860/128&mtu=1280&reserved={$reserved}&ifp=8-15&ifps=40-100&ifpd=20-250#{$hash}";
    $base64Reserved = decimalToBase64($reserved);
    $baseV2rayng = "wireguard://{$private_key}@{$ip}:{$port}?address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A8f81%3Ad551%3Aa0%3A532e%3Aa2b3%2F128&reserved=" . urlencode($reserved) . "&publickey={$public_key}&mtu=1280#{$hash}";
    return [
        $ip,
        $port,
        $private_key,
        $public_key,
        $reserved,
        "streisand://import/" . $baseStreisand, 
        "hiddify://import/" . $baseHiddify,
        $warpPlusKey,
        $baseV2rayng
    ];
}

function maskUrl($url) {
    return "https://axorax.github.io/urlmskr/" . base64_encode($url);
}

function generateWarpPlusKey() {
    $command = 'python main.py';
    exec($command, $output, $return_var);
    if ($return_var === 0) {
    // Command executed successfully, $output contains the response from the Python script
        $lastLineNumber = count($output) - 1;
        foreach ($output as $line) {
            echo $line . "\n";
        }
        $pattern = "/[a-zA-Z0-9]{8}-[a-zA-Z0-9]{8}-[a-zA-Z0-9]{8}/";
        preg_match_all($pattern, $output[$lastLineNumber], $matches);
        if (!empty($matches[0])) {
            return implode(", ", $matches[0]);
        } else {
            return null;
        }
    } else {
        // Command failed to execute
        echo "Python script could not be executed.";
        return null;
    }
}


$output = createWarp($choosenIp, $choosenPort);

$warpLicense = !is_null($output[7]) ? "WARP+ License = {$output[7]}" : "WARP+ License = NOT WARP+";

$configsJson = json_decode(file_get_contents("warpConfigs.json"), true) ?? [];

$configsJson[] = [
    "added" => time(),
    "ip" => $output[0],
    "port" => $output[1],
    "private_key" => $output[2],
    "peer_public_key" => $output[3],
    "reserved" => $output[4],
    "reserved(base64)" => decimalToBase64($output[4]),
    "key" => !is_null($output[7]) ? $output[7] : "Free WARP",
    "streisand" => $output[5],
    "hiddify" => $output[6],
    "v2rayng" => $output[8]
];

$configsOutput = json_encode($configsJson, JSON_PRETTY_PRINT);

file_put_contents("warpConfigs.json", $configsOutput);
