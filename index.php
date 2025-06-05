<?php
// Online NAT Type Detector
echo "<h1>在线 NAT 类型检测器</h1>";

// STUN Server Configuration
\$stun_server1_host = 'stun.l.google.com';
\$stun_server1_port = 19302;
\$stun_server2_host = 'stun.xten.com'; // Secondary STUN server for Symmetric NAT detection
\$stun_server2_port = 3478;
\$default_timeout = 3;

const MAGIC_COOKIE = "\x21\x12\xA4\x42";
const MAGIC_COOKIE_INT = 0x2112A442;

// --- Helper Functions (generateTransactionId, packStunAttributes, parseStunAttributeValue, parseStunResponse, sendStunRequest) ---
// [The helper functions from the previous step are assumed to be here and correct]
function generateTransactionId(): string {
    try {
        return random_bytes(12);
    } catch (Exception \$e) {
        return substr(md5(uniqid("stun", true) . microtime(true), true), 0, 12);
    }
}

function packStunAttributes(array \$attributes_array): string {
    \$binary_attributes = "";
    foreach (\$attributes_array as \$attr) {
        \$type = pack('n', \$attr['type']);
        \$value = \$attr['value'];
        \$length = pack('n', strlen(\$value));
        \$binary_attributes .= \$type . \$length . \$value;
        if ((\$attr_len_val = strlen(\$value)) % 4 != 0) {
            \$binary_attributes .= str_repeat("\x00", 4 - (\$attr_len_val % 4));
        }
    }
    return \$binary_attributes;
}

function parseStunAttributeValue(\$attr_type, \$attr_value_raw, \$transaction_id_12_byte) {
    if (\$attr_type === 0x0001) {
        if (strlen(\$attr_value_raw) < 8) return null;
        \$family = ord(substr(\$attr_value_raw, 1, 1));
        if (\$family !== 0x01) return null;
        \$port_raw = substr(\$attr_value_raw, 2, 2);
        \$ip_raw = substr(\$attr_value_raw, 4, 4);
        return ['ip' => inet_ntop(\$ip_raw), 'port' => unpack('n', \$port_raw)[1], 'is_xor' => false, 'type' => 'MAPPED-ADDRESS'];
    }
    if (\$attr_type === 0x0020) {
        if (strlen(\$attr_value_raw) < 8) return null;
        \$family = ord(substr(\$attr_value_raw, 1, 1));
        if (\$family !== 0x01) return null;
        \$xor_port_raw = substr(\$attr_value_raw, 2, 2);
        \$xor_ip_raw = substr(\$attr_value_raw, 4, 4);
        \$magic_cookie_msb16 = unpack('n', substr(MAGIC_COOKIE, 0, 2))[1];
        \$port = unpack('n', \$xor_port_raw)[1] ^ \$magic_cookie_msb16;
        \$xor_ip_int = unpack('N', \$xor_ip_raw)[1];
        \$ip_int = \$xor_ip_int ^ MAGIC_COOKIE_INT;
        \$ip = inet_ntop(pack('N', \$ip_int));
        return ['ip' => \$ip, 'port' => \$port, 'is_xor' => true, 'type' => 'XOR-MAPPED-ADDRESS'];
    }
    if (\$attr_type === 0x8020) {
        return ['warning' => 'Attribute type 0x8020 (obsolete XOR-MAPPED-ADDRESS) not fully implemented for XORing.'];
    }
    if (\$attr_type === 0x0005) {
         if (strlen(\$attr_value_raw) < 8) return null;
         \$family = ord(substr(\$attr_value_raw, 1, 1));
         if (\$family !== 0x01) return null;
         \$port_raw = substr(\$attr_value_raw, 2, 2);
         \$ip_raw = substr(\$attr_value_raw, 4, 4);
         return ['ip' => inet_ntop(\$ip_raw), 'port' => unpack('n', \$port_raw)[1], 'type' => 'CHANGED-ADDRESS'];
    }
    if (\$attr_type === 0x0004 || \$attr_type === 0x000A || \$attr_type === 0x8028) { // SOURCE-ADDRESS / REFLECTED-FROM / RESPONSE-ORIGIN
        if (strlen(\$attr_value_raw) < 8) return null;
        \$family = ord(substr(\$attr_value_raw, 1, 1));
        if (\$family !== 0x01) return null;
        \$port_raw = substr(\$attr_value_raw, 2, 2);
        \$ip_raw = substr(\$attr_value_raw, 4, 4);
        return ['ip' => inet_ntop(\$ip_raw), 'port' => unpack('n', \$port_raw)[1], 'type' => 'SOURCE-ADDRESS/REFLECTED-FROM'];
    }
    return null;
}

function parseStunResponse(string \$response_bytes, string \$expected_transaction_id_12_byte): ?array {
    if (strlen(\$response_bytes) < 20) return ['error' => 'Response too short (< 20 bytes)'];
    \$response_type_raw = substr(\$response_bytes, 0, 2);
    \$response_type = unpack('n', \$response_type_raw)[1];
    \$magic_cookie_recv = substr(\$response_bytes, 4, 4);
    if (\$magic_cookie_recv !== MAGIC_COOKIE) {
        // Could be an RFC3489 server, or just not STUN. For this code, we expect RFC5389 from primary.
        // For secondary server, we might be more lenient or have a different parsing path if needed.
        return ['error' => 'Magic Cookie mismatch. Expected: ' . bin2hex(MAGIC_COOKIE) . ', Got: ' . bin2hex(\$magic_cookie_recv)];
    }
    \$response_transaction_id_12_byte = substr(\$response_bytes, 8, 12);
    if (\$response_transaction_id_12_byte !== \$expected_transaction_id_12_byte) {
        return ['error' => 'Transaction ID mismatch. Expected: ' . bin2hex(\$expected_transaction_id_12_byte) . ', Got: ' . bin2hex(\$response_transaction_id_12_byte)];
    }
    \$result = [
        'message_type_hex' => bin2hex(\$response_type_raw),
        'attributes' => [],
        'mapped_address' => null,
        'source_address' => null,
        'changed_address' => null,
        'error_code' => null
    ];
    if (\$response_type !== 0x0101 && \$response_type !== 0x0111) {
        \$result['error'] = 'Not a STUN Binding Response (Type: 0x' . bin2hex(\$response_type_raw) . ')';
        return \$result;
    }
    \$attributes_data = substr(\$response_bytes, 20);
    \$offset = 0;
    while (\$offset < strlen(\$attributes_data)) {
        if (strlen(\$attributes_data) - \$offset < 4) break;
        \$attr_type = unpack('n', substr(\$attributes_data, \$offset, 2))[1];
        \$attr_length = unpack('n', substr(\$attributes_data, \$offset + 2, 2))[1];
        \$attr_value_offset = \$offset + 4;
        if (strlen(\$attributes_data) - \$attr_value_offset < \$attr_length) {
             \$result['error_details'] = "Attribute (type 0x".dechex(\$attr_type).") declared length ({\$attr_length}) exceeds remaining data.";
             break;
        }
        \$attr_value_raw = substr(\$attributes_data, \$attr_value_offset, \$attr_length);
        \$parsed_value = parseStunAttributeValue(\$attr_type, \$attr_value_raw, \$response_transaction_id_12_byte);
        if (\$parsed_value) {
            if (isset(\$parsed_value['warning'])) {
                 if(!isset(\$result['warnings'])) \$result['warnings'] = [];
                 \$result['warnings'][] = \$parsed_value['warning'];
            }
            \$attr_entry = ['type_hex' => dechex(\$attr_type), 'type_name' => \$parsed_value['type'] ?? 'Unknown', 'value' => \$parsed_value];
            \$result['attributes'][] = \$attr_entry;
            if (\$attr_type === 0x0001 || \$attr_type === 0x0020) {
                if (isset(\$parsed_value['ip']) && isset(\$parsed_value['port'])) {
                    \$result['mapped_address'] = \$parsed_value;
                }
            }
            if (\$attr_type === 0x0004 || \$attr_type === 0x000A || \$attr_type === 0x8028) {
                \$result['source_address'] = \$parsed_value;
            }
            if (\$attr_type === 0x0005) {
                \$result['changed_address'] = \$parsed_value;
            }
        }
        if (\$attr_type === 0x0009) {
            \$class = (ord(substr(\$attr_value_raw, 2, 1))) & 0x07;
            \$number = ord(substr(\$attr_value_raw, 3, 1));
            \$code = \$class * 100 + \$number;
            \$reason = substr(\$attr_value_raw, 4, \$attr_length - 4);
            \$result['error_code'] = ['code' => \$code, 'reason' => htmlspecialchars(\$reason)];
            \$result['error'] = "STUN Error Code: \$code - " . htmlspecialchars(\$reason);
        }
        \$offset += (4 + \$attr_length);
        if ((\$attr_length % 4) != 0) {
            \$offset += (4 - (\$attr_length % 4));
        }
    }
    return \$result;
}

function sendStunRequest(string \$server, int \$port, string \$transaction_id_12_byte, array \$attributes_to_pack = [], int \$timeout = 2, bool \$expect_rfc5389 = true): ?string {
    \$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    if (!\$socket) return null;
    \$timeout_array = array("sec" => \$timeout, "usec" => 0);
    socket_set_option(\$socket, SOL_SOCKET, SO_RCVTIMEO, \$timeout_array);
    socket_set_option(\$socket, SOL_SOCKET, SO_SNDTIMEO, \$timeout_array);
    \$message_type = "\x00\x01";
    \$packed_attributes = packStunAttributes(\$attributes_to_pack);
    \$message_length = pack('n', strlen(\$packed_attributes));

    \$header_part3 = \$expect_rfc5389 ? (MAGIC_COOKIE . \$transaction_id_12_byte) : \$transaction_id_12_byte; // Simplified for non-RFC5389, assumes 12 byte ID if not RFC5389.
                                                                                                     // A true RFC3489 would use a 16-byte transaction ID here.
                                                                                                     // This is a slight simplification for the secondary server if it's not strictly RFC5389.
    if (!\$expect_rfc5389 && strlen(\$transaction_id_12_byte) !== 16) {
        // If we claim not to expect RFC5389 (e.g. for an old STUN server)
        // we should ideally be using a 16 byte transaction ID.
        // Forcing 12 bytes for now for simplicity with generateTransactionId().
    }

    \$stun_request_header = \$message_type . \$message_length . \$header_part3;
    \$stun_request = \$stun_request_header . \$packed_attributes;

    if (socket_sendto(\$socket, \$stun_request, strlen(\$stun_request), 0, \$server, \$port) === false) {
        socket_close(\$socket);
        return null;
    }
    \$response_bytes = "";
    \$from_ip = "";
    \$from_port = 0;
    \$bytes_received = socket_recvfrom(\$socket, \$response_bytes, 2048, 0, \$from_ip, \$from_port);
    socket_close(\$socket);
    if (\$bytes_received === false || \$bytes_received === 0) {
        return null;
    }
    return \$response_bytes;
}

// --- Main Test Logic ---
set_time_limit(30); // Increase script execution time limit
echo "<h2>STUN Test Results (RFC 5389 Focus):</h2>";
\$nat_type_hypothesis = "未知 (Unknown)";
\$mapped_addr_test1 = null;
\$test_i_error = null;
\$test_ii_error = null;
\$test_iii_error = null;
\$test_iv_error = null;

// Test I
echo "<h3>Test I: 获取外部地址 (主 STUN 服务器: {\$stun_server1_host})</h3>";
\$tx_id1 = generateTransactionId();
\$raw_response1 = sendStunRequest(\$stun_server1_host, \$stun_server1_port, \$tx_id1, [], \$default_timeout, true);
if (\$raw_response1 === null) {
    \$test_i_error = "Test I: 未收到 STUN 服务器 {\$stun_server1_host} 的响应。";
    echo "<p style='color:red;'>{\$test_i_error}</p>";
} else {
    \$result1 = parseStunResponse(\$raw_response1, \$tx_id1);
    if (\$result1 && !isset(\$result1['error']) && isset(\$result1['mapped_address']['ip']) && isset(\$result1['mapped_address']['port'])) {
        \$mapped_addr_test1 = \$result1['mapped_address'];
        echo "<p style='color:green;'>Test I: 成功!</p>";
        echo "<ul><li>公网 IP: <strong>" . htmlspecialchars(\$mapped_addr_test1['ip']) . "</strong></li><li>公网端口: <strong>" . htmlspecialchars(\$mapped_addr_test1['port']) . "</strong></li><li>解析方式: " . htmlspecialchars(\$mapped_addr_test1['type']) . (\$mapped_addr_test1['is_xor'] ? " (XOR 解码)" : "") . "</li></ul>";
    } else {
        \$test_i_error = "Test I: 解析响应失败、包含错误或未找到有效的 Mapped Address。 ";
        if (\$result1 && isset(\$result1['error'])) \$test_i_error .= "错误信息: " . htmlspecialchars(\$result1['error']);
        echo "<p style='color:red;'>{\$test_i_error}</p>";
    }
}

// Test II
echo "<h3>Test II: 请求主 STUN 服务器从不同 IP 和端口响应</h3>";
\$test_ii_response_received = false;
if (\$mapped_addr_test1) {
    \$tx_id2 = generateTransactionId();
    \$change_request_value_T2 = pack('N', 0x00000006);
    \$attributes_test2 = [['type' => 0x0003, 'value' => \$change_request_value_T2]];
    \$raw_response2 = sendStunRequest(\$stun_server1_host, \$stun_server1_port, \$tx_id2, \$attributes_test2, \$default_timeout, true);
    if (\$raw_response2 === null) {
        \$test_ii_error = "Test II: 未收到 STUN 服务器对 CHANGE_REQUEST (IP&Port) 的响应。";
        echo "<p style='color:orange;'>{\$test_ii_error}</p>";
    } else {
        \$result2 = parseStunResponse(\$raw_response2, \$tx_id2);
        if (\$result2 && !isset(\$result2['error'])) {
            echo "<p style='color:green;'>Test II: 收到响应!</p>";
            \$test_ii_response_received = true;
        } else {
            \$test_ii_error = "Test II: 解析响应失败或响应包含错误。 ";
            if (\$result2 && isset(\$result2['error'])) \$test_ii_error .= "错误信息: " . htmlspecialchars(\$result2['error']);
            echo "<p style='color:red;'>{\$test_ii_error}</p>";
        }
    }
} else {
    echo "<p>由于 Test I 未成功，跳过 Test II。</p>";
}

// Test III
echo "<h3>Test III: 请求主 STUN 服务器仅从不同端口响应</h3>";
\$test_iii_response_received = false;
if (\$mapped_addr_test1 && !\$test_ii_response_received) {
    \$tx_id3 = generateTransactionId();
    \$change_request_value_T3 = pack('N', 0x00000002);
    \$attributes_test3 = [['type' => 0x0003, 'value' => \$change_request_value_T3]];
    \$raw_response3 = sendStunRequest(\$stun_server1_host, \$stun_server1_port, \$tx_id3, \$attributes_test3, \$default_timeout, true);
    if (\$raw_response3 === null) {
        \$test_iii_error = "Test III: 未收到 STUN 服务器对 CHANGE_REQUEST (Port only) 的响应。";
        echo "<p style='color:orange;'>{\$test_iii_error}</p>";
    } else {
        \$result3 = parseStunResponse(\$raw_response3, \$tx_id3);
        if (\$result3 && !isset(\$result3['error'])) {
            echo "<p style='color:green;'>Test III: 收到响应!</p>";
            \$test_iii_response_received = true;
        } else {
            \$test_iii_error = "Test III: 解析响应失败或响应包含错误。 ";
            if (\$result3 && isset(\$result3['error'])) \$test_iii_error .= "错误信息: " . htmlspecialchars(\$result3['error']);
            echo "<p style='color:red;'>{\$test_iii_error}</p>";
        }
    }
} else if (!\$mapped_addr_test1) {
    echo "<p>由于 Test I 未成功，跳过 Test III。</p>";
} else if (\$test_ii_response_received) {
    echo "<p>由于 Test II 已收到响应，通常不需要进行 Test III。</p>";
}

// Test IV (Symmetric NAT detection)
echo "<h3>Test IV: 获取外部地址 (辅助 STUN 服务器: {\$stun_server2_host})</h3>";
\$mapped_addr_test4 = null;
\$run_test_iv = false;
if (\$mapped_addr_test1) {
    if (\$test_ii_response_received) { // Full Cone or Open
        // No need for test IV if it's already likely Full Cone / Open
    } else {
        if (\$test_iii_response_received) { // Restricted Cone
            // No need for test IV if it's Restricted Cone
        } else { // Port Restricted Cone or Symmetric
            \$run_test_iv = true;
        }
    }
}

if (\$run_test_iv) {
    echo "<p>执行 Test IV 以尝试区分端口限制锥型和对称型 NAT...</p>";
    \$tx_id4 = generateTransactionId();
    // For secondary server, we might not be sure if it's strictly RFC5389.
    // Setting expect_rfc5389 to true, as parseStunResponse will check Magic Cookie.
    // If stun.xten.com is RFC3489, parseStunResponse will report a magic cookie error.
    \$raw_response4 = sendStunRequest(\$stun_server2_host, \$stun_server2_port, \$tx_id4, [], \$default_timeout, true);
    if (\$raw_response4 === null) {
        \$test_iv_error = "Test IV: 未收到辅助 STUN 服务器 {\$stun_server2_host} 的响应。对称型 NAT 检测可能不完整。";
        echo "<p style='color:orange;'>{\$test_iv_error}</p>";
    } else {
        \$result4 = parseStunResponse(\$raw_response4, \$tx_id4);
        if (\$result4 && !isset(\$result4['error']) && isset(\$result4['mapped_address']['ip']) && isset(\$result4['mapped_address']['port'])) {
            \$mapped_addr_test4 = \$result4['mapped_address'];
            echo "<p style='color:green;'>Test IV: 成功!</p>";
            echo "<ul><li>公网 IP (Mapped Address from {\$stun_server2_host}): <strong>" . htmlspecialchars(\$mapped_addr_test4['ip']) . "</strong></li><li>公网端口 (Mapped Port from {\$stun_server2_host}): <strong>" . htmlspecialchars(\$mapped_addr_test4['port']) . "</strong></li></ul>";
        } else {
            \$test_iv_error = "Test IV: 解析来自 {\$stun_server2_host} 的响应失败、包含错误或未找到有效的 Mapped Address。对称型 NAT 检测可能不完整。 ";
            if (\$result4 && isset(\$result4['error'])) \$test_iv_error .= "错误信息: " . htmlspecialchars(\$result4['error']);
             echo "<p style='color:red;'>{\$test_iv_error}</p>";
        }
    }
} else if (!\$mapped_addr_test1) {
    echo "<p>由于 Test I 未成功，跳过 Test IV。</p>";
} else {
    echo "<p>根据前序测试结果，不需要进行 Test IV。</p>";
}

// --- NAT Type Hypothesis ---
echo "<h3>最终 NAT 类型推断</h3>";
if (\$mapped_addr_test1) {
    if (\$test_ii_response_received) {
        \$nat_type_hypothesis = "开放型 (Open Internet) 或 完全锥型 (Full Cone NAT)";
    } else {
        if (\$test_iii_response_received) {
            \$nat_type_hypothesis = "限制锥型 (Restricted Cone NAT)";
        } else {
            // Test II and Test III failed. Now check Test IV results.
            if (\$run_test_iv && \$mapped_addr_test4) {
                if (\$mapped_addr_test1['ip'] === \$mapped_addr_test4['ip'] && \$mapped_addr_test1['port'] === \$mapped_addr_test4['port']) {
                    \$nat_type_hypothesis = "端口限制锥型 (Port Restricted Cone NAT)";
                } else {
                    \$nat_type_hypothesis = "对称型 (Symmetric NAT)";
                }
            } else if (\$run_test_iv && !\$mapped_addr_test4) {
                 \$nat_type_hypothesis = "端口限制锥型 (Port Restricted Cone NAT) 或 对称型 (Symmetric NAT) - Test IV 未成功，无法明确区分";
                 if(\$test_iv_error) echo "<p style='color:orange;'>由于 Test IV 未能从辅助STUN服务器获取有效映射地址，无法最终区分端口限制锥型和对称型NAT。</p>";
            } else {
                 \$nat_type_hypothesis = "端口限制锥型 (Port Restricted Cone NAT) 或 对称型 (Symmetric NAT) - Test IV 未执行";
            }
        }
    }
} else {
    \$nat_type_hypothesis = "未知 - Test I 未能获取基础映射地址";
    if(\$test_i_error) echo "<p style='color:red;'>由于 Test I 失败，无法进行 NAT 类型推断: " . htmlspecialchars(\$test_i_error) . "</p>";
}
echo "<p><strong>当前推断的 NAT 类型: " . htmlspecialchars(\$nat_type_hypothesis) . "</strong></p>";

// Display any errors from tests for clarity
if (!\$mapped_addr_test1 && \$test_i_error) { echo "<p style='color:magenta;'>Test I 错误详情: " . htmlspecialchars(\$test_i_error) . "</p>"; }
if (\$mapped_addr_test1 && !\$test_ii_response_received && \$test_ii_error) { echo "<p style='color:magenta;'>Test II 错误详情: " . htmlspecialchars(\$test_ii_error) . "</p>"; }
if (\$mapped_addr_test1 && !\$test_ii_response_received && !\$test_iii_response_received && \$test_iii_error) { echo "<p style='color:magenta;'>Test III 错误详情: " . htmlspecialchars(\$test_iii_error) . "</p>"; }
if (\$run_test_iv && !\$mapped_addr_test4 && \$test_iv_error) { echo "<p style='color:magenta;'>Test IV 错误详情: " . htmlspecialchars(\$test_iv_error) . "</p>"; }

echo "<hr><p><em>注意：这是一个基于 RFC 5780 (NAT Behavior Discovery using STUN) 中主要测试流程的 NAT 类型检测。结果可能受 STUN 服务器行为、网络条件及 PHP 环境限制。stun.xten.com 作为辅助服务器可能不稳定或不支持所有RFC5389特性。</em></p>";

?>
