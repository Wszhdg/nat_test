<?php
declare(strict_types=1);

// Assuming Logger is autoloaded or required before this class is used.
// If not, and Logger.php is in the same directory:
// require_once __DIR__ . '/Logger.php';

class StunAttribute {
    public int \$type;
    public string \$value; // Raw binary value

    public function __construct(int \$type, string \$value) {
        \$this->type = \$type;
        \$this->value = \$value;
    }

    public function getLength(): int {
        return strlen(\$this->value);
    }
}

class StunMessage {
    // STUN Message Types (RFC 5389)
    public const TYPE_BINDING_REQUEST = 0x0001;
    public const TYPE_BINDING_SUCCESS_RESPONSE = 0x0101;
    public const TYPE_BINDING_ERROR_RESPONSE = 0x0111;

    public const ATTR_MAPPED_ADDRESS = 0x0001;
    public const ATTR_USERNAME = 0x0006;
    public const ATTR_MESSAGE_INTEGRITY = 0x0008;
    public const ATTR_ERROR_CODE = 0x0009;
    public const ATTR_UNKNOWN_ATTRIBUTES = 0x000A;
    public const ATTR_REALM = 0x0014;
    public const ATTR_NONCE = 0x0015;
    public const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
    public const ATTR_SOFTWARE = 0x8022;
    public const ATTR_ALTERNATE_SERVER = 0x8023;
    public const ATTR_FINGERPRINT = 0x8028;

    public const ATTR_CHANGE_REQUEST = 0x0003;
    public const ATTR_CHANGED_ADDRESS = 0x0005;
    public const ATTR_SOURCE_ADDRESS = 0x0004;
    public const ATTR_RESPONSE_ORIGIN = 0x802b;
    public const ATTR_OTHER_ADDRESS = 0x802c;

    private const MAGIC_COOKIE = "\x21\x12\xA4\x42";
    private const MAGIC_COOKIE_INT = 0x2112A442;

    private int \$messageType;
    private string \$transactionId;
    /** @var StunAttribute[] */
    private array \$attributes = [];

    public function __construct(int \$messageType, ?string \$transactionId = null) {
        \$this->messageType = \$messageType;
        if (\$transactionId === null) {
            \$this->transactionId = static::generateTransactionId();
        } else {
            if (strlen(\$transactionId) !== 12) {
                throw new InvalidArgumentException("Transaction ID must be 12 bytes for RFC 5389.");
            }
            \$this->transactionId = \$transactionId;
        }
        Logger::debug("StunMessage created: Type 0x" . dechex(\$this->messageType) . ", TXID " . bin2hex(\$this->transactionId));
    }

    public static function generateTransactionId(): string {
        try {
            return random_bytes(12);
        } catch (Exception \$e) {
            return substr(md5(uniqid("stun", true) . microtime(true), true), 0, 12);
        }
    }

    public function getTransactionId(): string {
        return \$this->transactionId;
    }

    public function getMessageType(): int {
        return \$this->messageType;
    }

    public function addAttribute(int \$type, string \$rawValue): void {
        \$this->attributes[] = new StunAttribute(\$type, \$rawValue);
        Logger::debug("Attribute added: Type 0x" . dechex(\$type) . ", Length " . strlen(\$rawValue) . ", TXID " . bin2hex(\$this->transactionId));
    }

    public function getAttribute(int \$type): ?StunAttribute {
        foreach (\$this->attributes as \$attribute) {
            if (\$attribute->type === \$type) {
                return \$attribute;
            }
        }
        return null;
    }

    /** @return StunAttribute[] */
    public function getAttributes(): array {
        return \$this->attributes;
    }

    public function pack(): string {
        \$attributesBinary = "";
        foreach (\$this->attributes as \$attribute) {
            \$attributesBinary .= pack('n', \$attribute->type);
            \$attributesBinary .= pack('n', \$attribute->getLength());
            \$attributesBinary .= \$attribute->value;
            if ((\$len = \$attribute->getLength()) % 4 !== 0) {
                \$attributesBinary .= str_repeat("\x00", 4 - (\$len % 4));
            }
        }

        \$messageLength = strlen(\$attributesBinary);
        \$header = pack('n', \$this->messageType);
        \$header .= pack('n', \$messageLength);
        \$header .= self::MAGIC_COOKIE;
        \$header .= \$this->transactionId;

        Logger::debug("StunMessage packed: Total length " . (20 + \$messageLength) . ", TXID " . bin2hex(\$this->transactionId));
        return \$header . \$attributesBinary;
    }

    public static function parse(string \$binaryData, ?string \$expectedTransactionId = null, bool \$isStrictRfc5389 = true): ?StunMessage {
        Logger::debug("StunMessage::parse: Attempting to parse " . strlen(\$binaryData) . " bytes. Strict: " . (\$isStrictRfc5389 ? 'yes':'no') . ". Expected TXID: " . (\$expectedTransactionId ? bin2hex(\$expectedTransactionId) : 'N/A'));
        if (strlen(\$binaryData) < 20) {
            Logger::warning("StunMessage::parse: Data too short (< 20 bytes).");
            return null;
        }

        \$messageType = unpack('n', substr(\$binaryData, 0, 2))[1];
        \$messageLength = unpack('n', substr(\$binaryData, 2, 2))[1];
        \$magicCookie = substr(\$binaryData, 4, 4);
        \$transactionId = substr(\$binaryData, 8, 12);

        if (\$isStrictRfc5389 && \$magicCookie !== self::MAGIC_COOKIE) {
            Logger::warning("StunMessage::parse: Magic cookie mismatch (strict mode). Expected " . bin2hex(self::MAGIC_COOKIE) . " got " . bin2hex(\$magicCookie) . ". TXID: " . bin2hex(\$transactionId));
            return null;
        }
        if (!\$isStrictRfc5389 && \$magicCookie !== self::MAGIC_COOKIE) {
             Logger::info("StunMessage::parse: Magic cookie mismatch (non-strict mode), might be RFC3489 or other. Got " . bin2hex(\$magicCookie) . ". TXID: " . bin2hex(\$transactionId));
             // Potentially allow parsing to continue for non-strict cases if that's desired,
             // but for now, we'll still fail if it's not the RFC5389 magic cookie,
             // as this parser is primarily for RFC5389.
             // To support RFC3489 fully, a different parsing logic for header/attributes would be needed.
             // For now, let's assume if it's not the magic cookie, it's not a parseable STUN message for this class.
             return null;
        }


        if (\$expectedTransactionId !== null && \$transactionId !== \$expectedTransactionId) {
            Logger::error("StunMessage::parse: Transaction ID mismatch. Expected " . bin2hex(\$expectedTransactionId) . " got " . bin2hex(\$transactionId));
            return null;
        }

        if (strlen(substr(\$binaryData, 20)) < \$messageLength) {
            Logger::warning("StunMessage::parse: Actual attribute data length " . strlen(substr(\$binaryData, 20)) . " is less than declared message length {\$messageLength}. TXID: " . bin2hex(\$transactionId));
            return null;
        }

        \$msg = new StunMessage(\$messageType, \$transactionId);

        \$attributesData = substr(\$binaryData, 20, \$messageLength);
        \$offset = 0;
        while (\$offset < strlen(\$attributesData)) {
            if (strlen(\$attributesData) - \$offset < 4) {
                Logger::debug("StunMessage::parse: Not enough data for another attribute header. Offset: {\$offset}, Data Length: " . strlen(\$attributesData) . ". TXID: " . bin2hex(\$transactionId));
                break;
            }

            \$attrType = unpack('n', substr(\$attributesData, \$offset, 2))[1];
            \$attrLength = unpack('n', substr(\$attributesData, \$offset + 2, 2))[1];
            \$offset += 4;

            if (strlen(\$attributesData) - \$offset < \$attrLength) {
                Logger::warning("StunMessage::parse: Attribute 0x" . dechex(\$attrType) . " declared length {\$attrLength} exceeds available data ".(strlen(\$attributesData) - \$offset).". TXID: " . bin2hex(\$transactionId));
                return null;
            }
            \$attrValue = substr(\$attributesData, \$offset, \$attrLength);
            \$msg->addAttribute(\$attrType, \$attrValue); // Logging is inside addAttribute
            \$offset += \$attrLength;

            if ((\$attrLength % 4) !== 0) {
                \$offset += (4 - (\$attrLength % 4));
            }
        }
        Logger::debug("StunMessage::parse: Successfully parsed header and attributes for TXID: " . bin2hex(\$transactionId) . ". Message Type: 0x" . dechex(\$messageType));
        return \$msg;
    }

    public function getMappedAddress(): ?array {
        \$xorMappedAttr = \$this->getAttribute(self::ATTR_XOR_MAPPED_ADDRESS);
        if (\$xorMappedAttr) {
            \$rawValue = \$xorMappedAttr->value;
            if (strlen(\$rawValue) >= 8) {
                \$family = ord(substr(\$rawValue, 1, 1));
                if (\$family === 0x01) {
                    \$xorPortRaw = substr(\$rawValue, 2, 2);
                    \$xorIpRaw = substr(\$rawValue, 4, 4);
                    \$magicCookieMsb16 = unpack('n', substr(self::MAGIC_COOKIE, 0, 2))[1];
                    \$port = unpack('n', \$xorPortRaw)[1] ^ \$magicCookieMsb16;
                    \$xorIpInt = unpack('N', \$xorIpRaw)[1];
                    \$ipInt = \$xorIpInt ^ self::MAGIC_COOKIE_INT;
                    \$ip = inet_ntop(pack('N', \$ipInt));
                    Logger::debug("XOR-MAPPED-ADDRESS found: {\$ip}:{\$port}, TXID: " . bin2hex(\$this->transactionId));
                    return ['ip' => \$ip, 'port' => \$port, 'type' => 'XOR-MAPPED-ADDRESS'];
                }
            }
        }

        \$mappedAttr = \$this->getAttribute(self::ATTR_MAPPED_ADDRESS);
        if (\$mappedAttr) {
            \$rawValue = \$mappedAttr->value;
             if (strlen(\$rawValue) >= 8) {
                \$family = ord(substr(\$rawValue, 1, 1));
                if (\$family === 0x01) {
                    \$portRaw = substr(\$rawValue, 2, 2);
                    \$ipRaw = substr(\$rawValue, 4, 4);
                    \$ip = inet_ntop(\$ipRaw);
                    \$port = unpack('n', \$portRaw)[1];
                    Logger::debug("MAPPED-ADDRESS found: {\$ip}:{\$port}, TXID: " . bin2hex(\$this->transactionId));
                    return ['ip' => \$ip, 'port' => \$port, 'type' => 'MAPPED-ADDRESS'];
                }
            }
        }
        Logger::warning("No MAPPED-ADDRESS or XOR-MAPPED-ADDRESS found or parsed successfully. TXID: " . bin2hex(\$this->transactionId));
        return null;
    }

    public function getErrorCode(): ?array {
        \$errorAttr = \$this->getAttribute(self::ATTR_ERROR_CODE);
        if (\$errorAttr && \$errorAttr->getLength() >= 4) {
            \$rawValue = \$errorAttr->value;
            \$class = ord(substr(\$rawValue, 2, 1)) & 0x07;
            \$number = ord(substr(\$rawValue, 3, 1));
            \$code = \$class * 100 + \$number;
            \$reason = substr(\$rawValue, 4, \$errorAttr->getLength() - 4);
            Logger::warning("STUN Error Code attribute found: {\$code} - " . trim(\$reason) . ", TXID: " . bin2hex(\$this->transactionId));
            return ['code' => \$code, 'reason' => htmlspecialchars(trim(\$reason))];
        }
        return null;
    }

    public function getChangedAddress(): ?array {
        \$attr = \$this->getAttribute(self::ATTR_CHANGED_ADDRESS);
        if (\$attr) {
            \$rawValue = \$attr->value;
            if (strlen(\$rawValue) >= 8) {
                \$family = ord(substr(\$rawValue, 1, 1));
                if (\$family === 0x01) {
                    \$portRaw = substr(\$rawValue, 2, 2);
                    \$ipRaw = substr(\$rawValue, 4, 4);
                    \$ip = inet_ntop(\$ipRaw);
                    \$port = unpack('n', \$portRaw)[1];
                    Logger::debug("CHANGED-ADDRESS found: {\$ip}:{\$port}, TXID: " . bin2hex(\$this->transactionId));
                    return ['ip' => \$ip, 'port' => \$port, 'type' => 'CHANGED-ADDRESS'];
                }
            }
        }
        return null;
    }
}
?>
