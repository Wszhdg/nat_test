<?php
declare(strict_types=1);

class Logger {
    public const DEBUG = 0;
    public const INFO = 1;
    public const WARNING = 2;
    public const ERROR = 3;

    private static string \$logFilePath = __DIR__ . '/../app.log';
    private static int \$logLevel = self::INFO;
    private static bool \$logDirChecked = false;
    private static bool \$logDirWritable = false;

    public static function setLogFilePath(string \$path): void {
        if (substr(\$path, 0, 1) !== '/' && substr(\$path, 1, 2) !== ':\\') { // Basic check for Windows absolute path too
            // Assumes logs dir is intended to be relative to project root (parent of src)
            \$path = dirname(__DIR__) . '/' . ltrim(\$path, '/');
        }
        self::\$logFilePath = \$path;
        self::\$logDirChecked = false;
    }

    public static function setLogLevel(int \$level): void {
        self::\$logLevel = \$level;
    }

    private static function ensureLogDirectory(): bool {
        if (self::\$logDirChecked) {
            return self::\$logDirWritable;
        }

        \$logDir = dirname(self::\$logFilePath);
        if (!is_dir(\$logDir)) {
            if (!@mkdir(\$logDir, 0775, true) && !is_dir(\$logDir)) {
                error_log("Logger Critical Error: Failed to create log directory: {\$logDir}. Application logs to this path will be disabled.");
                self::\$logDirWritable = false;
            } else {
                self::\$logDirWritable = is_writable(\$logDir);
                if (!self::\$logDirWritable) {
                     error_log("Logger Critical Error: Log directory {\$logDir} created but is not writable. Application logs to this path will be disabled.");
                }
            }
        } else {
            self::\$logDirWritable = is_writable(\$logDir);
            if (!self::\$logDirWritable) {
                 error_log("Logger Warning: Log directory {\$logDir} exists but is not writable. Application logs to this path will be disabled.");
            }
        }
        self::\$logDirChecked = true;
        return self::\$logDirWritable;
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
        \$logEntry = "[{\$date}] [{\$levelStr}] {\$message}\n";

        if (self::ensureLogDirectory()) {
            if (@file_put_contents(self::\$logFilePath, \$logEntry, FILE_APPEND | LOCK_EX) === false) {
                error_log("Logger Error: Failed to write to log file: " . self::\$logFilePath . " for message: {\$message}");
            }
        } else {
            // Fallback log for the message itself if primary logging is down, already logged dir issue
            // error_log("Fallback Log (dir issue) [{\$levelStr}]: {\$message}");
        }
    }

    public static function debug(string \$message): void { self::log(self::DEBUG, \$message); }
    public static function info(string \$message): void { self::log(self::INFO, \$message); }
    public static function warning(string \$message): void { self::log(self::WARNING, \$message); }
    public static function error(string \$message): void { self::log(self::ERROR, \$message); }
}
?>
