<?php
declare(strict_types=1);

require_once __DIR__ . '/src/Logger.php'; // Load Logger first

\$config = require_once __DIR__ . '/config.php';

// Initialize Logger
if (isset(\$config['logging']['path'])) {
    Logger::setLogFilePath(\$config['logging']['path']);
}
\$logLevelName = \$config['logging']['level_name'] ?? 'INFO';
\$logLevels = ['DEBUG' => Logger::DEBUG, 'INFO' => Logger::INFO, 'WARNING' => Logger::WARNING, 'ERROR' => Logger::ERROR];
Logger::setLogLevel(\$logLevels[strtoupper(\$logLevelName)] ?? Logger::INFO);

Logger::debug("-------------------- New Request to stun_runner.php --------------------");

require_once __DIR__ . '/src/StunMessage.php';
require_once __DIR__ . '/src/StunClient.php';

header('Content-Type: application/json');

\$base_response = [
    'success' => false,
    'test_id' => null,
    'data' => null,
    'error' => 'Invalid request or test ID.'
];

\$test_id = $_GET['test_id'] ?? null;
Logger::info("Request received for test_id: " . var_export(\$test_id, true));
\$base_response['test_id'] = \$test_id;

\$default_timeout = (int)\$config['default_timeout_seconds'];

if (!\$test_id) {
    Logger::warning("No test_id provided.");
    echo json_encode(\$base_response);
    exit;
}

\$current_response = \$base_response;

try {
    Logger::debug("Processing test_id: {\$test_id}");
    switch (\$test_id) {
        case 'test1':
        case 'test_tcp1':
            \$protocol = (\$test_id === 'test_tcp1') ? 'tcp' : 'udp';
            Logger::info("Executing Test I ({\$protocol}) with primary server.");
            \$server_config = \$config['stun_servers']['primary'];
            \$client = new StunClient(
                \$server_config['host'], (int)\$server_config['port'],
                \$default_timeout, (bool)\$server_config['is_rfc5389_strict']
            );
            \$mapped_addr = \$client->discoverMappedAddress(\$protocol);
            if (\$mapped_addr) {
                \$current_response['success'] = true;
                \$current_response['data'] = \$mapped_addr;
                \$current_response['error'] = null;
                Logger::info("Test I ({\$protocol}) success: " . json_encode(\$mapped_addr));
            } else {
                \$current_response['success'] = false;
                \$current_response['error'] = "Test I ({\$protocol}): Failed to get Mapped Address from {\$server_config['host']}.";
                Logger::warning(\$current_response['error']);
            }
            break;
        case 'test2':
            Logger::info("Executing Test II with primary server.");
            \$server_config = \$config['stun_servers']['primary'];
            \$client = new StunClient(
                \$server_config['host'], (int)\$server_config['port'],
                \$default_timeout, (bool)\$server_config['is_rfc5389_strict']
            );
            \$test_ii_success = \$client->performTestIIChangeIpAndPort();
            \$current_response['success'] = true;
            \$current_response['data'] = ['response_received' => \$test_ii_success];
            \$current_response['error'] = null;
            Logger::info("Test II result: response_received = " . (\$test_ii_success ? 'true' : 'false'));
            break;
        case 'test3':
            Logger::info("Executing Test III with primary server.");
            \$server_config = \$config['stun_servers']['primary'];
            \$client = new StunClient(
                \$server_config['host'], (int)\$server_config['port'],
                \$default_timeout, (bool)\$server_config['is_rfc5389_strict']
            );
            \$test_iii_success = \$client->performTestIIIChangePortOnly();
            \$current_response['success'] = true;
            \$current_response['data'] = ['response_received' => \$test_iii_success];
            \$current_response['error'] = null;
            Logger::info("Test III result: response_received = " . (\$test_iii_success ? 'true' : 'false'));
            break;
        case 'test4':
            Logger::info("Executing Test IV with secondary server.");
            \$server_config = \$config['stun_servers']['secondary'];
            \$client = new StunClient(
                \$server_config['host'], (int)\$server_config['port'],
                \$default_timeout, (bool)\$server_config['is_rfc5389_strict']
            );
            \$mapped_addr = \$client->discoverMappedAddress('udp'); // Assuming Test IV is UDP
            if (\$mapped_addr) {
                \$current_response['success'] = true;
                \$current_response['data'] = \$mapped_addr;
                \$current_response['error'] = null;
                Logger::info("Test IV success: " . json_encode(\$mapped_addr));
            } else {
                \$current_response['success'] = false;
                \$current_response['error'] = "Test IV (UDP): Failed to get Mapped Address from {\$server_config['host']}.";
                Logger::warning(\$current_response['error']);
            }
            break;
        default:
            \$current_response['error'] = "Unknown test ID: {\$test_id}.";
            Logger::error(\$current_response['error']);
            break;
    }
} catch (Exception \$e) {
    \$current_response['success'] = false;
    \$current_response['error'] = "Server-side script exception: " . \$e->getMessage();
    Logger::error("Exception in stun_runner.php for test_id {\$test_id}: " . \$e->getMessage() . "\nTrace: " . \$e->getTraceAsString());
}

Logger::debug("Sending JSON response: " . json_encode(\$current_response));
echo json_encode(\$current_response);

?>
