<?php

namespace CompartSoftware\WebsocketServer;
use Socket;

class WebSocketServer
{
    private $host = '0.0.0.0';
    private $port = 8080;
    private $socket;
    private $clients = [];
    private $maxBufferSize = 65535;

    public function __construct($host = null, $port = null)
    {
        if ($host) $this->host = $host;
        if ($port) $this->port = $port;
    }

    public function start(): void
    {
        $this->createSocket();
        $this->bindSocket();
        $this->listenSocket();

        echo "WebSocket server started on $this->host:$this->port\n";

        while (true) {
            $changed = $this->clients;
            $null = NULL;
            socket_select($changed, $null, $null, 0, 10);

            if (in_array($this->socket, $changed)) {
                $this->handleNewConnection();
            }

            $this->processClientMessages($changed);
        }

        socket_close($this->socket);
    }

    private function createSocket(): void
    {
        $this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
        $this->clients[] = $this->socket;
    }

    private function bindSocket(): void
    {
        socket_bind($this->socket, $this->host, $this->port);
    }

    private function listenSocket(): void
    {
        socket_listen($this->socket);
    }

    private function handleNewConnection():void
    {
        $new_socket = socket_accept($this->socket);
        $this->clients[] = $new_socket;

        $header = socket_read($new_socket, 1024);
        $this->performHandshake($header, $new_socket);

        socket_getpeername($new_socket, $ip);
        echo "New connection from $ip\n";

        $response = $this->mask(json_encode(['type' => 'system', 'message' => $ip . ' connected']));
        $this->sendMessage($response);
    }

    private function processClientMessages(array $changed)
    {
        foreach ($changed as $changed_socket) {
            if ($changed_socket == $this->socket) continue; // Skip server socket

            $buf = '';
            $bytes = @socket_recv($changed_socket, $buf, 1024, 0);

            if ($bytes === false || $bytes === 0) {
                $this->handleDisconnection($changed_socket);
                continue;
            }

            if (strlen($buf) > $this->maxBufferSize) {
                $error_message = json_encode(["error" => "Message size exceeds buffer limit of $this->maxBufferSize bytes."]);
                socket_write($changed_socket, $this->mask($error_message), strlen($this->mask($error_message)));
                echo "Error: Message size exceeds buffer limit\n";
                continue;
            }

            $received_text = $this->unmask($buf);
            $message = json_decode($received_text, true);

            if (isset($message['name']) && isset($message['message'])) {
                $response_text = $this->mask(json_encode(['type' => 'usermsg', 'name' => $message['name'], 'message' => $message['message']]));
                $this->sendMessage($response_text);
                echo "Message from {$message['name']}: {$message['message']}\n";
            } else {
                $error_response = json_encode(['error' => 'Invalid message format']);
                socket_write($changed_socket, $this->mask($error_response), strlen($this->mask($error_response)));
                echo "Error: Invalid message format\n";
            }
        }
    }

    private function performHandshake(string $header, Socket $client_socket): void
    {
        $headers = [];
        $lines = preg_split("/\r\n/", $header);
        foreach ($lines as $line) {
            $line = chop($line);
            if (preg_match('/\A(\S+): (.*)\z/', $line, $matches)) {
                $headers[$matches[1]] = $matches[2];
            }
        }

        $sec_websocket_key = $headers['Sec-WebSocket-Key'];
        $sec_websocket_accept = base64_encode(pack('H*', sha1($sec_websocket_key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
        $handshake_response = "HTTP/1.1 101 Switching Protocols\r\n" .
            "Upgrade: websocket\r\n" .
            "Connection: Upgrade\r\n" .
            "Sec-WebSocket-Accept: $sec_websocket_accept\r\n\r\n";
        socket_write($client_socket, $handshake_response, strlen($handshake_response));
        echo "Handshake completed with client\n";
    }

    private function unmask(string $text): string
    {
        $length = ord($text[1]) & 127;
        if ($length == 126) {
            $masks = substr($text, 4, 4);
            $data = substr($text, 8);
        } elseif ($length == 127) {
            $masks = substr($text, 10, 4);
            $data = substr($text, 14);
        } else {
            $masks = substr($text, 2, 4);
            $data = substr($text, 6);
        }
        $text = '';
        for ($i = 0; $i < strlen($data); ++$i) {
            $text .= $data[$i] ^ $masks[$i % 4];
        }
        return $text;
    }

    private function mask(string $text): string
    {
        $b1 = 0x80 | (0x1 & 0x0f);
        $length = strlen($text);

        if ($length <= 125) {
            $header = pack('CC', $b1, $length);
        } elseif ($length > 125 && $length < 65536) {
            $header = pack('CCn', $b1, 126, $length);
        } elseif ($length >= 65536) {
            $header = pack('CCNN', $b1, 127, $length);
        } else {
            return json_encode(['error' => 'Message length exceeds the maximum allowed limit']);
        }

        return $header . $text;
    }

    private function sendMessage(string $msg): void
    {
        foreach ($this->clients as $client) {
            @socket_write($client, $msg, strlen($msg));
        }
    }

    private function handleDisconnection(Socket $socket): void
    {
        socket_getpeername($socket, $ip);
        $response = $this->mask(json_encode(['type' => 'system', 'message' => $ip . ' disconnected']));
        $this->sendMessage($response);

        $found_socket = array_search($socket, $this->clients);
        if ($found_socket !== false) {
            unset($this->clients[$found_socket]);
            socket_close($socket);
            echo "Client disconnected: $ip\n";
        }
    }
}

// Usage
$server = new WebSocketServer();
$server->start();
