# PHP 在线 NAT 类型检测器

本项目是一个使用 PHP 和 STUN (Session Traversal Utilities for NAT) 协议实现的在线 NAT (网络地址转换) 类型检测工具。它可以帮助用户了解其当前网络环境的 NAT 类型，这对于 P2P 应用（如在线游戏、文件共享、VoIP）的连接性至关重要。

## 主要功能特性

*   **全面的 NAT 类型检测**:
    *   通过与 STUN 服务器进行一系列 UDP 测试，遵循 RFC 5389 和 RFC 5780 (NAT Behavior Discovery) 的主要原则。
    *   能够区分多种 NAT 类型，包括：开放型 (Open Internet)、完全锥型 (Full Cone)、限制锥型 (Restricted Cone)、端口限制锥型 (Port Restricted Cone) 和对称型 (Symmetric NAT)。
*   **支持 TCP STUN 测试**:
    *   可以执行基础的 STUN over TCP 测试，获取通过 TCP 连接时的公网映射地址。
*   **异步执行与动态更新**:
    *   采用 AJAX 技术异步执行各个 STUN 测试，用户界面会动态更新每个测试的进度和结果，无需等待所有测试完成。
*   **可配置性**:
    *   STUN 服务器（主服务器和辅助服务器）、端口、超时时间以及日志级别均可通过 `config.php` 文件进行配置。
*   **详细日志记录**:
    *   内置日志系统，可记录详细的操作信息和错误，方便问题排查。
*   **友好的用户界面**:
    *   清晰展示每个测试步骤的结果和最终的 NAT 类型推断。
    *   提供“复制结果”功能，方便用户分享或记录检测信息。
*   **纯 PHP 后端**:
    *   核心检测逻辑使用 PHP 实现，易于部署在常见的 Web 服务器环境中。

## 技术栈

*   **后端**: PHP (推荐 PHP 7.4+，使用了 `match` 表达式和严格类型)
    *   需要 PHP `sockets` 扩展用于网络通信。
    *   需要 PHP `json` 扩展 (通常默认启用)。
*   **前端**: HTML, CSS, JavaScript (ES6+ for `async/await` features in AJAX calls)
*   **协议**: STUN (RFC 5389, RFC 5780)

## 项目结构

```
.
├── src/                     # PHP 核心类目录
│   ├── StunClient.php       # STUN 客户端逻辑，执行测试
│   ├── StunMessage.php      # STUN 消息构建与解析
│   └── Logger.php           # 日志记录类
├── logs/                    # 日志文件存放目录 (可配置)
│   └── stun_app.log         # 默认日志文件
├── index.php                # 前端主页面和 JavaScript 逻辑
├── stun_runner.php          # 后端 AJAX 请求处理脚本，执行 STUN 测试
├── config.php               # 项目配置文件 (需要用户手动创建或复制)
└── README.md                # 本文档
```

## 安装与配置

1.  **环境要求**:
    *   Web 服务器 (例如 Apache, Nginx) 并已正确配置 PHP。
    *   PHP 版本 >= 7.4 (推荐 8.0+)。
    *   确保 PHP `sockets` 扩展已启用。

2.  **部署步骤**:
    *   将项目文件克隆或下载到您的 Web 服务器的文档可访问目录下。
    *   **创建配置文件**: 项目中不直接包含 `config.php`。您需要手动创建一个 `config.php` 文件在项目根目录下。可以参考以下模板：
        ```php
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
                'level_name' => 'INFO', // 可选值: DEBUG, INFO, WARNING, ERROR
                'path' => __DIR__ . '/logs/stun_app.log'
            ]
        ];
        ?>
        ```
    *   **目录权限**:
        *   PHP 脚本需要有权限读取 `src/` 目录下的文件和 `config.php`。
        *   如果 `logs/` 目录（或您在 `config.php` 中指定的其他日志路径的父目录）不存在，PHP 脚本会尝试创建它。请确保 Web 服务器运行 PHP 的用户对项目根目录（或日志文件目标目录的父目录）具有写权限。或者，您可以手动创建 `logs` 目录并赋予 PHP 写权限。

3.  **配置 STUN 服务器**:
    *   编辑 `config.php` 文件，根据需要修改主 STUN 服务器 (`primary`) 和辅助 STUN 服务器 (`secondary`) 的地址和端口。
    *   `is_rfc5389_strict` 参数指示是否严格要求服务器遵守 RFC5389规范（例如，发送 Magic Cookie）。对于公共 STUN 服务器，此行为可能有所不同。

4.  **配置日志**:
    *   在 `config.php` 中，您可以设置 `logging.level_name` (DEBUG, INFO, WARNING, ERROR) 和 `logging.path` (日志文件路径)。建议在生产环境中设置为 `INFO` 或 `WARNING`，在开发或调试时设置为 `DEBUG`。

## 如何使用

1.  通过 Web 浏览器访问您部署的 `index.php` 文件。
2.  点击页面上的“开始检测”按钮。
3.  脚本将依次执行一系列 STUN 测试，并在页面上动态显示每个测试的结果。
4.  所有测试完成后，页面将显示推断出的 NAT 类型和相关的网络信息。
5.  您可以使用“复制结果”按钮将关键信息复制到剪贴板。

## NAT 类型解释

理解您的 NAT 类型有助于判断 P2P 连接的难易程度：

*   **开放型 (Open Internet)**: 您的设备直接连接到互联网，没有 NAT。或者您的 NAT 行为非常开放，几乎等同于直接连接。P2P 连接通常没有问题。
*   **完全锥型 (Full Cone NAT)**: 一旦您的设备通过 NAT 将内部 IP 地址和端口映射到一个公网 IP 地址和端口，任何外部主机都可以通过向该公网映射发送数据包来到达您的内部设备和端口。这是对 P2P 最友好的 NAT 类型。
*   **限制锥型 (Restricted Cone NAT)**: 与完全锥型类似，但增加了限制：只有当您的内部设备之前向某个外部主机的 IP 地址 X 发送过数据后，该外部主机 X 才能向您的公网映射（任何端口）发送数据包。
*   **端口限制锥型 (Port Restricted Cone NAT)**: 比限制锥型更严格。只有当您的内部设备之前向某个外部主机的 IP 地址 X 和端口 P 发送过数据后，该外部主机 X 才能通过其源端口 P 向您的公网映射发送数据包。
*   **对称型 (Symmetric NAT)**: 这是限制最严格的 NAT 类型。当您的设备与特定目标 IP 地址和端口通信时，NAT 会为其创建一个唯一的公网 IP 和端口映射。来自同一内部 IP 和端口到不同目标 IP 或端口的请求，NAT 会使用不同的映射。这意味着只有您之前连接过的那个特定外部主机（IP和端口完全匹配）才能向该映射回送数据。对称型 NAT 通常需要借助中继服务器（如 TURN 服务器）来实现 P2P 通信。
*   **未知**: 由于测试未能完成或结果不明确，无法判断 NAT 类型。

## 故障排除

*   **检测失败/无响应**:
    *   检查您的网络连接。
    *   确认 PHP `sockets` 扩展已安装并启用。
    *   检查服务器防火墙或网络防火墙是否阻止了到 STUN 服务器端口（通常是 UDP/TCP 3478 或 19302）的出站连接。
    *   查看 `config.php` 中配置的日志文件路径下的日志（例如 `logs/stun_app.log`），将日志级别设置为 `DEBUG` 以获取最详细信息。
*   **辅助 STUN 服务器问题**:
    *   公共 STUN 服务器的可用性无法保证。如果 Test IV 失败，可能是因为辅助 STUN 服务器 (`stun.xten.com` 或您配置的其他服务器) 暂时不可用或不再运行。这会影响对称型 NAT 的准确判断。

## 贡献

欢迎通过提交 Issues 或 Pull Requests 来改进此项目。

## 许可证

本项目采用 MIT 许可证。详情请参阅 `LICENSE` 文件（如果未来添加）。
