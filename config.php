<?php
// config.php
return [
    'stun_servers' => [
        'primary' => [
            'host' => 'stun.l.google.com',
            'port' => 19302,
            'is_rfc5389_strict' => true
        ],
        'secondary' => [
            'host' => 'stun.xten.com',
            'port' => 3478,
            'is_rfc5389_strict' => false
        ],
    ],
    'default_timeout_seconds' => 3,
    'logging' => [
        'level_name' => 'DEBUG', // Set to DEBUG for more verbose logging during development
        'path' => __DIR__ . '/logs/stun_tester.log' // Log file in a 'logs' directory in project root
    ]
];
?>
