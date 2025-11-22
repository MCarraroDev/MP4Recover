<?php
  declare(strict_types=1);
  define('disable_sanitize_output', 'true');
  require __DIR__ . '/config.php';
  require __DIR__ . '/languages.php';

  ob_start();
  ini_set('display_errors', '0');
  error_reporting(E_ALL);

  set_error_handler(function($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) return;
    throw new ErrorException($message, 0, $severity, $file, $line);
  });

  set_exception_handler(function($e) {
    http_response_code(500);
    $msg = "Internal Server Error: " . $e->getMessage() . " @ " . $e->getFile() . ":" . $e->getLine();
    $buf = ob_get_contents();
    if ($buf === false || $buf === '') {
      header('Content-Type: text/plain; charset=utf-8');
      echo $msg;
    } else {
      echo "\n\n".$msg;
    }
    exit;
  });

  register_shutdown_function(function() {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
      http_response_code(500);
      header('Content-Type: text/plain; charset=utf-8');
      while (ob_get_level() > 0) { ob_end_clean(); }
      echo "Internal Server Error (fatal): {$err['message']} @ {$err['file']}:{$err['line']}";
    }
  });

  function fail(string $msg, int $code=400) : never {
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo "エラー: " . $msg;
    exit;
  }

  if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    fail(__('err_post_required'), 405);
  }

  if (!isset($_FILES['broken']) || $_FILES['broken']['error'] !== UPLOAD_ERR_OK) {
    fail(__('err_upload_failed'));
  }

  $broken_tmp  = $_FILES['broken']['tmp_name'];
  $broken_name = $_FILES['broken']['name'] ?? 'broken.mp4';

  $ref_present = isset($_FILES['reference']) && $_FILES['reference']['error'] === UPLOAD_ERR_OK;

  $in_dir = '/data/in';
  if (!is_dir($in_dir)) { if (!@mkdir($in_dir, 0775, true)) fail(__('err_mkdir_failed'), 500); }

  $broken_base = bin2hex(random_bytes(12)).".mp4";
  $broken_dst  = $in_dir . '/' . $broken_base;
  if (!move_uploaded_file($broken_tmp, $broken_dst)) {
    $perm = @decoct(@fileperms($in_dir) & 0777);
    $uid  = function_exists('posix_getuid') ? @posix_getuid() : -1;
    $gid  = function_exists('posix_getgid') ? @posix_getgid() : -1;
    fail(__('err_save_failed') . " dir_perm={$perm} uid={$uid} gid={$gid}", 500);
  }

  $ref_base = null; $ref_dst = null; $ref_name = null;
  if ($ref_present) {
    $ref_tmp  = $_FILES['reference']['tmp_name'];
    $ref_name = $_FILES['reference']['name'] ?? 'reference.mp4';
    $ref_base = bin2hex(random_bytes(12)).".mp4";
    $ref_dst  = $in_dir . '/' . $ref_base;
    if (!move_uploaded_file($ref_tmp, $ref_dst)) {
      fail(__('err_save_failed'), 500);
    }
  }

  $query = http_build_query([
    'src'    => $broken_base,
    'ref'    => $ref_base,
    'orig'   => $broken_name,
    'reforig'=> $ref_name
  ]);
  $api = ORCHESTRATOR_BASE . "/start?" . $query;

  $ch = curl_init();
  curl_setopt_array($ch, [
    CURLOPT_URL => $api,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT_MS => 5000,
    CURLOPT_TIMEOUT_MS => 30000,
  ]);
  $resp = curl_exec($ch);
  $http = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
  $cerr = curl_error($ch);
  curl_close($ch);

  if ($resp === false) {
    fail(__('err_curl_error', $cerr), 502);
  }
  if ($http >= 300) {
    fail(__('err_http_error', $http, $resp), 502);
  }

  $data = json_decode($resp, true);
  if (!$data || !isset($data['job_id'])) {
    fail(__('err_internal_comm') . " resp=".substr((string)$resp,0,512), 502);
  }

  $job = $data['job_id'];

  if (ob_get_length() !== false) { ob_end_clean(); }
  header("Location: status.php?job=" . urlencode($job));
  exit;
