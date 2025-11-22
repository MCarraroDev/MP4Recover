<?php
  // Configuration file

  declare(strict_types=1);
  define( "LOAD_START_TIME", microtime( true ) );

  $API_BASE = getenv('API_BASE') ?: 'http://mp4-repair:8000';

  $DATA_IN  = getenv('DATA_IN')  ?: '/data/in';
  $DATA_OUT = getenv('DATA_OUT') ?: '/data/out';

  define('ORCHESTRATOR_BASE', $API_BASE);

  header( "Access-Control-Allow-Origin:" );
  header( "Strict-Transport-Security: max-age=63072000; preload" );
  header( "X-Permitted-Cross-Domain-Policies: none" );
  header( "Referrer-Policy: same-origin" );

  // Function to compress HTML
  function sanitize_output($buffer) {

    // Random alphanumeric string to prevent XSS attacks
    define( "FLG", substr( base_convert( sha1( md5( uniqid() ) . md5 ( microtime() ) ), 16, 36), 0, 5) );

    // Processing when Content-Type is not HTML
    foreach(headers_list() as $line)
    {
      list($title, $data) = explode(": ", $line, 2);
      if (strtolower($title) == "content-type" && false === strpos($data, "text/html"))
        return $buffer;
    }

    // Processing tags where line breaks inside matter
    $buffer = preg_replace_callback("/<pre.*?<\/pre>/is", function($matches) {
      return "_" . FLG . "_here___prf__start" . base64_encode(urlencode($matches[0])) . "_" . FLG . "_here___prf__end";
    }, $buffer);
    $buffer = preg_replace_callback("/<script.*?<\/script>/is", function($matches) {
      return "_" . FLG . "_here___sct__start" . base64_encode(urlencode($matches[0])) . "_" . FLG . "_here___sct__end";
    }, $buffer);
    $buffer = preg_replace_callback("/<textarea.*?<\/textarea>/is", function($matches) {
      return "_" . FLG . "_here___txs__start" . base64_encode(urlencode($matches[0])) . "_" . FLG . "_here___txs__end";
    }, $buffer);

    // Remove line breaks and whitespace
    $buffer = preg_replace(array("/\>[^\S]+/s", "/[^\S]+\</s", "/(\s)+/s" ), array(">", "<", " "), $buffer);

    // Restore tags where line breaks matter
    $buffer = preg_replace_callback("/_" . FLG . "_here___prf__start.*?_" . FLG . "_here___prf__end/is", function($matches) {
      return urldecode(base64_decode(substr(substr($matches[0], 24), 0, -22)));
    }, $buffer);
    $buffer = preg_replace_callback("/_" . FLG . "_here___sct__start.*?_" . FLG . "_here___sct__end/is", function($matches) {
      return urldecode(base64_decode(substr(substr($matches[0], 24), 0, -22)));
    }, $buffer);
    $buffer = preg_replace_callback("/_" . FLG . "_here___txs__start.*?_" . FLG . "_here___txs__end/is", function($matches) {
      return urldecode(base64_decode(substr(substr($matches[0], 24), 0, -22)));
    }, $buffer);

    // Add comment after DOCTYPE declaration
    if (substr($buffer, 0, 15) == "<!DOCTYPE html>")
      $buffer = substr($buffer, 15);

    return
      "<!DOCTYPE html><!--\n" .
        "\n" .
        "  MP4Recover / (c) 2025 MCarraroDev.\n\n" .
        "  Server-Side Time: " . ( microtime( true ) - LOAD_START_TIME ) . "s\n" .
      "\n-->" . $buffer . "\n";

    return $buffer . "\n";
  }

  if (!defined('disable_sanitize_output'))
    ob_start( "sanitize_output" );

  function random_basename(string $ext): string {
    $hex = bin2hex(random_bytes(16));
    $e = strtolower($ext);
    $e = preg_replace('/[^a-z0-9]/', '', $e);
    if ($e === '') $e = 'bin';
    return "in_{$hex}.{$e}";
  }

  function secure_filename(string $name): string {
    $base = basename($name);
    // Use only for display (do not use for saving!)
    return $base;
  }

  function curl_get_json(string $url, array $params = [], int $timeout = 30): array {
    $ch = curl_init();
    if (!empty($params)) {
        $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($params);
    }
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_FAILONERROR => false,
    ]);
    $res = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    if ($res === false) {
        throw new RuntimeException("HTTP GET failed: {$err}");
    }
    $json = json_decode($res, true);
    if ($http >= 400) {
        $msg = is_array($json) && isset($json['detail']) ? $json['detail'] : $res;
        throw new RuntimeException("HTTP status {$http}: " . json_encode($json, JSON_UNESCAPED_UNICODE));
    }
    return is_array($json) ? $json : [];
  }

  function curl_post_json(string $url, array $params = [], int $timeout = 30): array {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($params),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_FAILONERROR => false,
    ]);
    $res = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    if ($res === false) {
        throw new RuntimeException("HTTP POST failed: {$err}");
    }
    $json = json_decode($res, true);
    if ($http >= 400) {
        $msg = is_array($json) && isset($json['detail']) ? $json['detail'] : $res;
        throw new RuntimeException("HTTP status {$http}: " . json_encode($json, JSON_UNESCAPED_UNICODE));
    }
    return is_array($json) ? $json : [];
  }
