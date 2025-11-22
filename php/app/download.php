<?php
  declare(strict_types=1);
  require __DIR__ . '/config.php';

  $job = isset($_GET['job']) ? (string)$_GET['job'] : '';
  if ($job === '' || !preg_match('/^[0-9a-f]{32}$/', $job)) {
    http_response_code(400); echo "invalid job"; exit;
  }
  $path = rtrim($DATA_OUT, '/').'/'.$job.'.mp4';
  if (!is_file($path)) {
    http_response_code(404); echo "not found"; exit;
  }
  $size = filesize($path);

  $filename = 'recovered_' . $job .' .mp4';
  # If filename is passed, use it as the filename
  if (isset($_GET['filename']) && !empty($_GET['filename'])) {
    $filename = 'recovered_' . str_replace('"', ' ', basename($_GET['filename']));
  }

  header('Content-Type: video/mp4');
  header('Content-Length: '.$size);
  header('Content-Disposition: attachment; filename="'.$filename.'"');
  readfile($path);
