<?php
declare(strict_types=1);

class Logger {
    public const DEBUG = 0;
    public const INFO = 1;
    public const WARNING = 2;
    public const ERROR = 3;

    private static string \$logFilePath = __DIR__ . '/../app.log'; // Default log path, relative to src/
    private static int \$logLevel = self::INFO;

    public static function setLogFilePath(string \$path): void {
        // Ensure the path is absolute or resolve it correctly
        if (substr(\$path, 0, 1) !== '/' && substr(\$path, 1, 2) !== ':\\') { // Basic check for absolute path
            \$path = dirname(__DIR__) . '/' . \$path; // Assuming logs dir is sibling to src or project root
        }
        self::\$logFilePath = \$path;
    }

    public static function setLogLevel(int \$level): void {
        self::\$logLevel = \$level;
    }

    private static function log(int \$level, string \$message): void {
        if (\$level < self::\$logLevel) {
            return;
        }

        \$levelStr = match (\$level) {
            self::DEBUG => 'DEBUG',
            self::INFO => 'INFO',
            self::WARNING => 'WARNING',
            self::ERROR => 'ERROR',
            default => 'UNKNOWN',
        };

        \$date = date('Y-m-d H:i:s');
        // Add microtime for more precise timing if needed: \$date = date('Y-m-d H:i:s.u');
        \$logEntry = "[{\$date}] [{\$levelStr}] {\$message}\n";

        \$logDir = dirname(self::\$logFilePath);
        if (!is_dir(\$logDir)) {
            if (!mkdir(\$logDir, 0775, true) && !is_dir(\$logDir)) {
                // Optionally, trigger an error or fallback if directory creation fails
                // error_log("Failed to create log directory: {\$logDir}");
                return; // Cannot write log
            }
        }

        @file_put_contents(self::\$logFilePath, \$logEntry, FILE_APPEND | LOCK_EX);
    }

    public static function debug(string \$message): void { self::log(self::DEBUG, \$message); }
    public static function info(string \$message): void { self::log(self::INFO, \$message); }
    public static function warning(string \$message): void { self::log(self::WARNING, \$message); }
    public static function error(string \$message): void { self::log(self::ERROR, \$message); }
}
?>
