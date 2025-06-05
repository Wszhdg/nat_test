<?php
declare(strict_types=1);

// require_once __DIR__ . '/StunMessage.php';
// require_once __DIR__ . '/Logger.php'; // Assuming autoloader or already included by runner

class StunClient {
    private string \$serverHost;
    private int \$serverPort;
    private int \$timeoutSeconds;
    private bool \$isStrictRfc5389;

    public function __construct(string \$serverHost, int \$serverPort, int \$timeoutSeconds = 2, bool \$isStrictRfc5389 = true) {
        \$this->serverHost = \$serverHost;
        \$this->serverPort = \$serverPort;
        \$this->timeoutSeconds = \$timeoutSeconds;
        \$this->isStrictRfc5389 = \$isStrictRfc5389;
        Logger::debug("StunClient initialized for {\$this->serverHost}:{\$this->serverPort}. Strict RFC5389: " . (\$isStrictRfc5389 ? 'Yes' : 'No'));
    }

    private function sendAndReceiveUdp(StunMessage \$requestMessage): ?StunMessage {
        Logger::debug("StunClient: Attempting UDP send to {\$this->serverHost}:{\$this->serverPort}, TXID: " . bin2hex(\$requestMessage->getTransactionId()));
        \$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if (!\$socket) {
            Logger::error("StunClient: Failed to create UDP socket: " . socket_strerror(socket_last_error()));
            return null;
        }

        \$timeout_array = ["sec" => \$this->timeoutSeconds, "usec" => 0];
        socket_set_option(\$socket, SOL_SOCKET, SO_RCVTIMEO, \$timeout_array);
        socket_set_option(\$socket, SOL_SOCKET, SO_SNDTIMEO, \$timeout_array);

        \$requestBinary = \$requestMessage->pack();
        if (socket_sendto(\$socket, \$requestBinary, strlen(\$requestBinary), 0, \$this->serverHost, \$this->serverPort) === false) {
            Logger::error("StunClient: Failed to send UDP STUN request to {\$this->serverHost}:{\$this->serverPort}. " . socket_strerror(socket_last_error(\$socket)));
            socket_close(\$socket);
            return null;
        }

        \$responseBinary = "";
        \$from_ip = "";
        \$from_port = 0;
        \$bytes_received = socket_recvfrom(\$socket, \$responseBinary, 2048, 0, \$from_ip, \$from_port);
        socket_close(\$socket);

        if (\$bytes_received === false || \$bytes_received === 0) {
            Logger::warning("StunClient: No UDP response or error receiving from {\$this->serverHost}:{\$this->serverPort}. TXID: " . bin2hex(\$requestMessage->getTransactionId()));
            return null;
        }
        Logger::debug("StunClient: Received UDP data (" . strlen(\$responseBinary) . " bytes) from {\$from_ip}:{\$from_port}. TXID: " . bin2hex(\$requestMessage->getTransactionId()));
        return StunMessage::parse(\$responseBinary, \$requestMessage->getTransactionId(), \$this->isStrictRfc5389);
    }

    private function sendAndReceiveTcp(StunMessage \$requestMessage): ?StunMessage {
        Logger::debug("StunClient: Attempting TCP connection to {\$this->serverHost}:{\$this->serverPort}");
        \$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if (!\$socket) {
            Logger::error("StunClient TCP Error: Failed to create socket: " . socket_strerror(socket_last_error()));
            return null;
        }

        \$timeout_array = ["sec" => \$this->timeoutSeconds, "usec" => 0];
        socket_set_option(\$socket, SOL_SOCKET, SO_RCVTIMEO, \$timeout_array);
        socket_set_option(\$socket, SOL_SOCKET, SO_SNDTIMEO, \$timeout_array);

        if (!socket_connect(\$socket, \$this->serverHost, \$this->serverPort)) {
            Logger::error("StunClient TCP Error: Failed to connect to {\$this->serverHost}:{\$this->serverPort}. " . socket_strerror(socket_last_error(\$socket)));
            socket_close(\$socket);
            return null;
        }
        Logger::debug("StunClient: TCP connected. Sending STUN request, TXID: " . bin2hex(\$requestMessage->getTransactionId()));

        \$requestBinary = \$requestMessage->pack();
        \$messageWithTcpFraming = pack('n', strlen(\$requestBinary)) . \$requestBinary;

        if (socket_write(\$socket, \$messageWithTcpFraming, strlen(\$messageWithTcpFraming)) === false) {
            Logger::error("StunClient TCP Error: Failed to write STUN request. " . socket_strerror(socket_last_error(\$socket)));
            socket_close(\$socket);
            return null;
        }

        \$lengthPrefix = socket_read(\$socket, 2);
        if (\$lengthPrefix === false || strlen(\$lengthPrefix) < 2) {
            Logger::warning("StunClient TCP Error: Failed to read response length prefix. TXID: " . bin2hex(\$requestMessage->getTransactionId()));
            socket_close(\$socket);
            return null;
        }
        \$responseLength = unpack('n', \$lengthPrefix)[1];
        Logger::debug("StunClient: TCP response length prefix indicates {\$responseLength} bytes. TXID: " . bin2hex(\$requestMessage->getTransactionId()));

        \$responseBinary = '';
        if (\$responseLength > 0) {
            \$bytes_to_read = \$responseLength;
            while(\$bytes_to_read > 0) {
                \$buffer = socket_read(\$socket, \$bytes_to_read);
                if (\$buffer === false || \$buffer === '') { // Empty string can mean connection closed
                    Logger::error("StunClient TCP Error: Failed to read full STUN response or connection closed prematurely. Expected {\$responseLength}, got " . strlen(\$responseBinary) . ". TXID: " . bin2hex(\$requestMessage->getTransactionId()));
                    socket_close(\$socket);
                    return null;
                }
                \$responseBinary .= \$buffer;
                \$bytes_to_read = \$responseLength - strlen(\$responseBinary);
            }
        }

        socket_close(\$socket);
        Logger::debug("StunClient: Received TCP data (" . strlen(\$responseBinary) . " bytes). TXID: " . bin2hex(\$requestMessage->getTransactionId()));
        return StunMessage::parse(\$responseBinary, \$requestMessage->getTransactionId(), \$this->isStrictRfc5389);
    }

    public function discoverMappedAddress(string \$protocol = 'udp'): ?array {
        Logger::info("StunClient: discoverMappedAddress called with protocol '{\$protocol}'.");
        \$request = new StunMessage(StunMessage::TYPE_BINDING_REQUEST);
        \$response = null;
        if (strtolower(\$protocol) === 'udp') {
            \$response = \$this->sendAndReceiveUdp(\$request);
        } elseif (strtolower(\$protocol) === 'tcp') {
            \$response = \$this->sendAndReceiveTcp(\$request);
        } else {
            Logger::error("StunClient: Unsupported protocol for discoverMappedAddress: {\$protocol}");
            throw new InvalidArgumentException("Unsupported protocol: \$protocol");
        }

        if (\$response && \$response->getMessageType() === StunMessage::TYPE_BINDING_SUCCESS_RESPONSE) {
            \$mappedAddress = \$response->getMappedAddress();
            if (\$mappedAddress) {
                 Logger::info("StunClient: Mapped address via {\$protocol} found: " . json_encode(\$mappedAddress));
            } else {
                 Logger::warning("StunClient: Mapped address via {\$protocol} not found in STUN response. TXID: " . bin2hex(\$request->getTransactionId()));
            }
            return \$mappedAddress;
        }
        Logger::warning("StunClient: No successful STUN binding response or error for discoverMappedAddress ({\$protocol}). TXID: " . bin2hex(\$request->getTransactionId()));
        if (\$response && \$response->getErrorCode()){
             Logger::warning("StunClient: Server returned error code: " . json_encode(\$response->getErrorCode()));
        }
        return null;
    }

    public function performTestIIChangeIpAndPort(): bool {
        Logger::info("StunClient: Performing Test II (Change IP & Port) via UDP.");
        \$request = new StunMessage(StunMessage::TYPE_BINDING_REQUEST);
        \$changeRequestValue = pack('N', 0x00000006);
        \$request->addAttribute(StunMessage::ATTR_CHANGE_REQUEST, \$changeRequestValue);
        \$response = \$this->sendAndReceiveUdp(\$request);
        \$responseReceived = \$response !== null;
        Logger::info("StunClient: Test II response_received: " . (\$responseReceived ? 'true' : 'false'));
        return \$responseReceived;
    }

    public function performTestIIIChangePortOnly(): bool {
        Logger::info("StunClient: Performing Test III (Change Port only) via UDP.");
        \$request = new StunMessage(StunMessage::TYPE_BINDING_REQUEST);
        \$changeRequestValue = pack('N', 0x00000002);
        \$request->addAttribute(StunMessage::ATTR_CHANGE_REQUEST, \$changeRequestValue);
        \$response = \$this->sendAndReceiveUdp(\$request);
        \$responseReceived = \$response !== null;
        Logger::info("StunClient: Test III response_received: " . (\$responseReceived ? 'true' : 'false'));
        return \$responseReceived;
    }
}
?>
