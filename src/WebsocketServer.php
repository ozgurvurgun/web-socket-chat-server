<?php

namespace CompartSoftware\WebsocketServer;

use Exception;
use Socket;

class WebSocketServer
{
    private string $host;
    private int $port;
    private Socket $socket;
    private array $clients = [];
    private int $maxBufferSize = 65535;

    public function __construct(string $host = '0.0.0.0', int $port = 8080)
    {
        $this->host = $host;
        $this->port = $port;
    }

    public function start(): void
    {
        $this->createSocket();
        $this->bindSocket();
        $this->listenSocket();
        $this->log("WebSocket server started on $this->host:$this->port");

        while (true) {
            $read_sockets = $this->clients;
            $write_sockets = null;
            $except_sockets = null;

            // Select sockets with a timeout of 10 seconds
            if (socket_select($read_sockets, $write_sockets, $except_sockets, 10) === false) {
                $this->logError("socket_select() failed: " . socket_strerror(socket_last_error()));
                continue;
            }

            if (in_array($this->socket, $read_sockets)) {
                $this->handleNewConnection();
            }

            $this->processClientMessages($read_sockets);
        }
    }

    private function createSocket(): void
    {
        $this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($this->socket === false) {
            throw new Exception("Unable to create socket: " . socket_strerror(socket_last_error()));
        }
        socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
        $this->clients[] = $this->socket;
    }

    private function bindSocket(): void
    {
        if (socket_bind($this->socket, $this->host, $this->port) === false) {
            throw new Exception("Unable to bind socket: " . socket_strerror(socket_last_error($this->socket)));
        }
    }

    private function listenSocket(): void
    {
        if (socket_listen($this->socket) === false) {
            throw new Exception("Unable to listen on socket: " . socket_strerror(socket_last_error($this->socket)));
        }
    }

    private function handleNewConnection(): void
    {
        $new_socket = socket_accept($this->socket);
        if ($new_socket === false) {
            $this->logError("Unable to accept new connection: " . socket_strerror(socket_last_error($this->socket)));
            return;
        }

        $this->clients[] = $new_socket;

        $header = socket_read($new_socket, 1024);
        if ($header === false) {
            $this->logError("Failed to read handshake header.");
            return;
        }

        $this->performHandshake($header, $new_socket);

        socket_getpeername($new_socket, $ip);
        $this->log("New connection from $ip");

        $response = $this->mask(json_encode(['type' => 'system', 'message' => "$ip connected"]));
        $this->sendMessage($response);
    }

    private function processClientMessages(array $changed): void
    {
        foreach ($changed as $socket) {
            if ($socket === $this->socket) continue;

            $buf = '';
            $bytes = @socket_recv($socket, $buf, $this->maxBufferSize, 0);

            if ($bytes === false || $bytes === 0) {
                $this->handleDisconnection($socket);
                continue;
            }

            if (strlen($buf) > $this->maxBufferSize) {
                $error_message = json_encode(["error" => "Message size exceeds buffer limit of $this->maxBufferSize bytes."]);
                socket_write($socket, $this->mask($error_message), strlen($this->mask($error_message)));
                $this->log("Error: Message size exceeds buffer limit");
                continue;
            }

            $received_text = $this->unmask($buf);
            $message = json_decode($received_text, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                $error_response = json_encode(['error' => 'Invalid JSON format']);
                socket_write($socket, $this->mask($error_response), strlen($this->mask($error_response)));
                $this->log("Error: Invalid JSON format");
                continue;
            }

            if (isset($message['name']) && isset($message['message'])) {
                $response_text = $this->mask(json_encode(['type' => 'usermsg', 'name' => htmlspecialchars($message['name']), 'message' => htmlspecialchars($message['message'])]));
                $this->sendMessage($response_text);
                $this->log("Message from {$message['name']}: {$message['message']}");
            } else {
                $error_response = json_encode(['error' => 'Invalid message format']);
                socket_write($socket, $this->mask($error_response), strlen($this->mask($error_response)));
                $this->log("Error: Invalid message format");
            }
        }
    }

    private function performHandshake(string $header, Socket $client_socket): void
    {
        $headers = [];
        $lines = preg_split("/\r\n/", $header);
        foreach ($lines as $line) {
            $line = trim($line);
            if (preg_match('/\A(\S+): (.*)\z/', $line, $matches)) {
                $headers[$matches[1]] = $matches[2];
            }
        }

        if (!isset($headers['Sec-WebSocket-Key'])) {
            throw new Exception("Missing Sec-WebSocket-Key header.");
        }

        $sec_websocket_key = $headers['Sec-WebSocket-Key'];
        $sec_websocket_accept = base64_encode(pack('H*', sha1($sec_websocket_key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
        $handshake_response = "HTTP/1.1 101 Switching Protocols\r\n" .
            "Upgrade: websocket\r\n" .
            "Connection: Upgrade\r\n" .
            "Sec-WebSocket-Accept: $sec_websocket_accept\r\n\r\n";
        socket_write($client_socket, $handshake_response, strlen($handshake_response));
        $this->log("Handshake completed with client");
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
        } else {
            $header = pack('CCNN', $b1, 127, $length);
        }

        return $header . $text;
    }

    private function sendMessage(string $msg): void
    {
        foreach ($this->clients as $client) {
            if ($client !== $this->socket) { // Skip the server socket
                @socket_write($client, $msg, strlen($msg));
            }
        }
    }

    private function handleDisconnection(Socket $socket): void
    {
        socket_getpeername($socket, $ip);
        $response = $this->mask(json_encode(['type' => 'system', 'message' => "$ip disconnected"]));
        $this->sendMessage($response);

        $found_socket = array_search($socket, $this->clients, true);
        if ($found_socket !== false) {
            unset($this->clients[$found_socket]);
            socket_close($socket);
            $this->log("Client disconnected: $ip");
        }
    }

    private function log(string $message): void
    {
        echo "$message\n";
        flush();
    }

    private function logError(string $message): void
    {
        error_log($message);
    }
}
