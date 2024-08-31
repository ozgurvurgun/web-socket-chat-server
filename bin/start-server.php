<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/WebSocketServer.php';

use CompartSoftware\WebsocketServer\WebSocketServer;

$server = new WebSocketServer();
$server->start();