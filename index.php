<?php
declare(strict_types=1);
\$config = require_once __DIR__ . '/config.php';
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>在线 NAT 类型检测器 (AJAX)</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
            margin: 0;
            padding: 20px;
            background-color: #f0f2f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            background-color: #ffffff;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-width: 800px;
            margin: 20px auto;
        }
        h1 { color: #1a237e; text-align: center; margin-bottom: 25px; }
        h2 { color: #283593; border-bottom: 2px solid #e8eaf6; padding-bottom: 10px; margin-top: 30px;}
        h3 { color: #3949ab; margin-bottom: 8px; }
        button#startNatTestBtn {
            display: block;
            width: 100%;
            max-width: 250px;
            margin: 20px auto;
            padding: 12px 20px;
            background-color: #3f51b5; /* Indigo */
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s ease;
        }
        button#startNatTestBtn:hover {
            background-color: #303f9f;
        }
        button#startNatTestBtn:disabled {
            background-color: #9fa8da;
            cursor: not-allowed;
        }
        button#copyResultsBtn {
            padding: 8px 12px;
            background-color: #4caf50; /* Green */
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            margin-left: 15px;
            vertical-align: middle;
            transition: background-color 0.3s ease;
        }
        button#copyResultsBtn:hover {
            background-color: #388e3c;
        }

        .test-result {
            margin-bottom: 20px;
            padding: 15px;
            border: 1px solid #e0e0e0;
            border-left: 5px solid #5c6bc0; /* Indigo lighter */
            border-radius: 4px;
            background-color: #f9f9f9;
        }
        .test-result h3 { margin-top: 0; font-size: 1.1em; }
        .status { font-weight: bold; }
        .status-success { color: #2e7d32; } /* Darker Green */
        .status-error { color: #c62828; }   /* Darker Red */
        .status-warning { color: #ef6c00; } /* Darker Orange */
        .data {
            margin-top: 5px;
            font-size: 0.95em;
            word-break: break-all; /* Prevent long strings from breaking layout */
        }
        .data strong { color: #1a237e; }
        .loader {
            display: none;
            margin-left: 8px;
            border: 3px solid #e0e0e0; /* Light grey */
            border-top: 3px solid #3f51b5; /* Indigo */
            border-radius: 50%;
            width: 16px;
            height: 16px;
            animation: spin 0.8s linear infinite;
            vertical-align: middle;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        #finalNatTypeResultContainer {
            padding: 15px;
            background-color: #e8eaf6;
            border-radius: 4px;
            margin-top: 10px;
            display: flex; /* Use flexbox for alignment */
            align-items: center; /* Vertically align items */
            justify-content: space-between; /* Space out NAT type and button */
            flex-wrap: wrap; /* Allow wrapping on smaller screens */
        }
        #finalNatType {
            font-weight: bold;
            font-size: 1.25em;
            color: #1a237e;
            margin-right: 15px; /* Add some space between text and button */
        }
        #overallStatus { margin-top: 15px; font-style: italic; color: #555;}
        #copyStatus { font-size:0.9em; color: #4caf50; margin-top: 5px; min-height: 1em; display: block; text-align: right;}
        hr { border: 0; height: 1px; background-color: #e0e0e0; margin: 30px 0; }
        p em { font-size: 0.9em; color: #555; }
    </style>
</head>
<body>
    <div class="container">
        <h1>在线 NAT 类型检测器</h1>
        <p>点击下面的按钮开始检测您的 NAT 类型。测试将依次执行，请耐心等待。</p>
        <button id="startNatTestBtn">开始检测 <span id="btnLoader" class="loader"></span></button>

        <h2>检测结果:</h2>
        <div id="testResultsContainer">
            <div id="test1Result" class="test-result" style="display:none;">
                <h3>Test I: 获取外部地址 (主 STUN 服务器: <?php echo htmlspecialchars(\$config['stun_servers']['primary']['host']); ?>)</h3>
                <p class="status"></p><p class="data"></p>
            </div>
            <div id="test2Result" class="test-result" style="display:none;">
                <h3>Test II: 请求主 STUN 服务器从不同 IP 和端口响应</h3>
                <p class="status"></p><p class="data"></p>
            </div>
            <div id="test3Result" class="test-result" style="display:none;">
                <h3>Test III: 请求主 STUN 服务器仅从不同端口响应</h3>
                <p class="status"></p><p class="data"></p>
            </div>
            <div id="test4Result" class="test-result" style="display:none;">
                <h3>Test IV: 获取外部地址 (辅助 STUN 服务器: <?php echo htmlspecialchars(\$config['stun_servers']['secondary']['host']); ?>)</h3>
                <p class="status"></p><p class="data"></p>
            </div>
            <div id="test_tcp1Result" class="test-result" style="display:none;">
                <h3>Test TCP I: 获取外部地址 (TCP, 主 STUN 服务器: <?php echo htmlspecialchars(\$config['stun_servers']['primary']['host']); ?>)</h3>
                <p class="status"></p><p class="data"></p>
            </div>
        </div>

        <h2>最终 NAT 类型推断:</h2>
        <div id="finalNatTypeResultContainer">
            <span id="finalNatType">尚未开始检测</span>
            <button id="copyResultsBtn" style="display:none;">复制结果</button>
        </div>
        <p id="copyStatus"></p>
        <p id="overallStatus"></p>
        <hr>
        <p><em>注意：这是一个基于 STUN 的 NAT 类型检测。结果可能受网络条件、STUN 服务器行为及 PHP 环境限制。</em></p>
    </div>

    <script>
        const startBtn = document.getElementById('startNatTestBtn');
        const btnLoader = document.getElementById('btnLoader');
        // const resultsContainer = document.getElementById('testResultsContainer'); // Not directly used in this version of JS
        const finalNatTypeEl = document.getElementById('finalNatType');
        const overallStatusEl = document.getElementById('overallStatus');
        const copyResultsBtn = document.getElementById('copyResultsBtn');
        const copyStatusEl = document.getElementById('copyStatus');

        let testData = {
            test1: { result: null, error: null, mapped_address: null, element: document.getElementById('test1Result') },
            test2: { result: null, error: null, response_received: false, element: document.getElementById('test2Result') },
            test3: { result: null, error: null, response_received: false, element: document.getElementById('test3Result') },
            test4: { result: null, error: null, mapped_address: null, element: document.getElementById('test4Result') },
            test_tcp1: { result: null, error: null, mapped_address: null, element: document.getElementById('test_tcp1Result') }
        };

        async function runTest(testId) {
            const currentTest = testData[testId];
            if (!currentTest || !currentTest.element) return false;

            currentTest.element.style.display = 'block';
            const statusEl = currentTest.element.querySelector('.status');
            const dataEl = currentTest.element.querySelector('.data');
            statusEl.className = 'status status-warning';
            statusEl.textContent = '正在执行...';
            dataEl.textContent = '';
            currentTest.error = null; // Reset error before test
            currentTest.result = null; // Reset result
            if(currentTest.mapped_address) currentTest.mapped_address = null;
            if(currentTest.hasOwnProperty('response_received')) currentTest.response_received = false;

            try {
                const response = await fetch(`stun_runner.php?test_id=\${testId}`);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: \${response.status}`);
                }
                const json = await response.json();
                currentTest.result = json;

                if (json.success) {
                    statusEl.className = 'status status-success';
                    statusEl.textContent = '成功!';
                    if (json.data) {
                        if (testId === 'test1' || testId === 'test4' || testId === 'test_tcp1') {
                            currentTest.mapped_address = json.data;
                            dataEl.innerHTML = `公网 IP: <strong>\${json.data.ip}</strong>, 端口: <strong>\${json.data.port}</strong>, 类型: \${json.data.type}`;
                        } else if (testId === 'test2' || testId === 'test3') {
                            currentTest.response_received = json.data.response_received;
                            dataEl.textContent = json.data.response_received ? '收到响应。' : '未收到响应。';
                        }
                    }
                } else {
                    currentTest.error = json.error || '未知错误';
                    statusEl.className = 'status status-error';
                    statusEl.textContent = '测试失败!';
                    dataEl.textContent = currentTest.error;
                }
            } catch (e) {
                currentTest.error = e.message;
                statusEl.className = 'status status-error';
                statusEl.textContent = '请求失败!';
                dataEl.textContent = currentTest.error;
            }
            updateFinalNatType();
            return !currentTest.error; // Return true if no error, false otherwise
        }

        function updateFinalNatType() {
            let hypothesis = "检测中...";
            const t1 = testData.test1;
            const t2 = testData.test2;
            const t3 = testData.test3;
            const t4 = testData.test4;
            // const t_tcp1 = testData.test_tcp1; // For future use in hypothesis if needed
            let canCopy = false;

            if (t1.error || !t1.result) { // If t1.result is null, it means test hasn't run or fetch failed before json parsing
                hypothesis = "未知 - Test I 失败或未完成";
            } else if (t1.mapped_address) {
                canCopy = true;
                if (!t2.result && !t2.error) { // Test 2 not yet run
                    hypothesis = "检测中... (等待 Test II)";
                } else if (t2.error) {
                     hypothesis = "NAT 类型未知 (Test II 执行出错)";
                } else if (t2.data && t2.data.response_received) {
                    hypothesis = "开放型 (Open Internet) 或 完全锥型 (Full Cone NAT)";
                } else { // Test II no response
                    if (!t3.result && !t3.error) {
                        hypothesis = "检测中... (等待 Test III)";
                    } else if (t3.error) {
                        hypothesis = "NAT 类型未知 (Test III 执行出错)";
                    } else if (t3.data && t3.data.response_received) {
                        hypothesis = "限制锥型 (Restricted Cone NAT)";
                    } else { // Test II and III no response
                        if (!t4.result && !t4.error) {
                            hypothesis = "检测中... (等待 Test IV)";
                        } else if (t4.error) {
                            hypothesis = "端口限制锥型 或 对称型 (Test IV 失败，无法区分)";
                        } else if (t4.mapped_address) {
                            if (t1.mapped_address.ip === t4.mapped_address.ip && t1.mapped_address.port === t4.mapped_address.port) {
                                hypothesis = "端口限制锥型 (Port Restricted Cone NAT)";
                            } else {
                                hypothesis = "对称型 (Symmetric NAT)";
                            }
                        } else { // Test IV ran but didn't provide mapped_address and no explicit error
                            hypothesis = "端口限制锥型 或 对称型 (Test IV 未提供明确区分信息)";
                        }
                    }
                }
            }
            finalNatTypeEl.textContent = hypothesis;
            copyResultsBtn.style.display = canCopy ? 'inline-block' : 'none';
            if (!canCopy) copyStatusEl.textContent = '';
        }

        startBtn.addEventListener('click', async () => {
            startBtn.disabled = true;
            btnLoader.style.display = 'inline-block';
            overallStatusEl.textContent = '正在执行所有测试...';
            finalNatTypeEl.textContent = '检测中...';
            copyResultsBtn.style.display = 'none';
            copyStatusEl.textContent = '';

            document.querySelectorAll('.test-result').forEach(el => {
                el.style.display = 'none';
                el.querySelector('.status').textContent = '';
                el.querySelector('.data').textContent = '';
            });
            // Reset internal data store
            for (const key in testData) {
                testData[key].result = null;
                testData[key].error = null;
                if(testData[key].hasOwnProperty('mapped_address')) testData[key].mapped_address = null;
                if(testData[key].hasOwnProperty('response_received')) testData[key].response_received = false;
            }

            if (await runTest('test1') && testData.test1.mapped_address) {
                if (await runTest('test2') && testData.test2.result && !testData.test2.result.data.response_received) {
                    if(await runTest('test3') && testData.test3.result && !testData.test3.result.data.response_received){
                         await runTest('test4');
                    }
                }
            }

            // Optionally, run TCP test regardless of UDP outcomes for informational purposes
            overallStatusEl.textContent = '正在执行 TCP 测试...';
            await runTest('test_tcp1');
            // Note: TCP test result is not currently part of NAT hypothesis.

            startBtn.disabled = false;
            btnLoader.style.display = 'none';
            overallStatusEl.textContent = '所有测试已完成。';
            updateFinalNatType(); // Final update after all relevant tests are done
        });

        copyResultsBtn.addEventListener('click', () => {
            let textToCopy = `NAT 类型: \${finalNatTypeEl.textContent}`;
            if (testData.test1.mapped_address) {
                textToCopy += `\n公网 IP (主): \${testData.test1.mapped_address.ip}`;
                textToCopy += `\n公网端口 (主): \${testData.test1.mapped_address.port}`;
            }
            if (testData.test4.mapped_address) {
                 textToCopy += `\n公网 IP (辅): \${testData.test4.mapped_address.ip}`;
                 textToCopy += `\n公网端口 (辅): \${testData.test4.mapped_address.port}`;
            }

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(textToCopy).then(() => {
                    copyStatusEl.textContent = '结果已复制到剪贴板!';
                    setTimeout(() => { copyStatusEl.textContent = ''; }, 2000);
                }).catch(err => {
                    copyStatusEl.textContent = '复制失败: ' + err;
                });
            } else {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = textToCopy;
                textArea.style.position = 'fixed'; // Prevent scrolling to bottom
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                try {
                    document.execCommand('copy');
                    copyStatusEl.textContent = '结果已复制到剪贴板 (fallback)!';
                    setTimeout(() => { copyStatusEl.textContent = ''; }, 2000);
                } catch (err) {
                    copyStatusEl.textContent = '复制失败 (fallback): ' + err;
                }
                document.body.removeChild(textArea);
            }
        });

    </script>
</body>
</html>
