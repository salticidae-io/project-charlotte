<?php
header('Content-Type: text/plain; charset=utf-8');
echo "Charlotte supervised PHP FastCGI is running.\n";
echo 'SAPI: ' . PHP_SAPI . "\n";
echo 'PHP version: ' . PHP_VERSION . "\n";
echo 'Process id: ' . getmypid() . "\n";
echo 'Request method: ' . ($_SERVER['REQUEST_METHOD'] ?? 'unknown') . "\n";
echo 'Script name: ' . ($_SERVER['SCRIPT_NAME'] ?? 'unknown') . "\n";
echo 'Query string: ' . ($_SERVER['QUERY_STRING'] ?? '') . "\n";
echo 'Server protocol: ' . ($_SERVER['SERVER_PROTOCOL'] ?? 'unknown') . "\n";
echo 'Remote address: ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n";