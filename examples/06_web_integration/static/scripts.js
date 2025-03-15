document.addEventListener('DOMContentLoaded', function() {
    // 获取DOM元素
    const scanForm = document.getElementById('scanForm');
    const scanButton = document.getElementById('scanButton');
    const scanStatus = document.getElementById('scanStatus');
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const scanSummary = document.getElementById('scanSummary');
    const resultsTable = document.getElementById('resultsTable');
    const resultsBody = document.getElementById('resultsBody');

    // 监听表单提交
    scanForm.addEventListener('submit', function(e) {
        e.preventDefault();
        startScan();
    });

    // 开始扫描
    function startScan() {
        // 获取表单数据
        const formData = new FormData(scanForm);
        const scanData = {
            target: formData.get('target'),
            ports: formData.get('ports'),
            scan_type: formData.get('scanType'),
            enable_os: formData.get('enableOS') === 'on',
            concurrency: parseInt(formData.get('concurrency')),
            timeout: parseInt(formData.get('timeout'))
        };

        // 更新UI状态
        scanButton.disabled = true;
        scanStatus.textContent = '扫描中...';
        scanStatus.style.backgroundColor = '#f39c12';
        progressContainer.style.display = 'block';
        resultsTable.style.display = 'none';
        scanSummary.textContent = '';
        resultsBody.innerHTML = '';

        // 动画进度条
        let progress = 0;
        const progressInterval = setInterval(() => {
            progress += 1;
            if (progress > 95) {
                clearInterval(progressInterval);
            }
            progressBar.style.width = `${progress}%`;
        }, 500);

        // 发送API请求
        fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(scanData)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP错误! 状态: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // 完成进度条
            clearInterval(progressInterval);
            progressBar.style.width = '100%';
            
            // 处理结果
            if (data.success) {
                displayResults(data);
                scanStatus.textContent = '扫描完成';
                scanStatus.style.backgroundColor = '#2ecc71';
            } else {
                throw new Error(data.error || '扫描失败');
            }
        })
        .catch(error => {
            // 错误处理
            clearInterval(progressInterval);
            scanStatus.textContent = '扫描失败';
            scanStatus.style.backgroundColor = '#e74c3c';
            scanSummary.textContent = `错误: ${error.message}`;
            console.error('扫描出错:', error);
        })
        .finally(() => {
            // 恢复按钮状态
            scanButton.disabled = false;
        });
    }

    // 显示扫描结果
    function displayResults(data) {
        // 显示摘要信息
        const openPorts = data.results.filter(r => r.state === 'open').length;
        const closedPorts = data.results.filter(r => r.state === 'closed').length;
        const filteredPorts = data.results.filter(r => r.state === 'filtered').length;
        
        scanSummary.innerHTML = `
            <strong>扫描目标:</strong> ${data.results[0]?.target || data.target}<br>
            <strong>扫描时长:</strong> ${data.duration.toFixed(2)} 秒<br>
            <strong>端口统计:</strong> 总计 ${data.results.length} 个端口 (开放: ${openPorts}, 关闭: ${closedPorts}, 过滤: ${filteredPorts})<br>
            <strong>开始时间:</strong> ${new Date(data.start_time).toLocaleString()}<br>
            <strong>结束时间:</strong> ${new Date(data.end_time).toLocaleString()}
        `;

        // 如果没有端口，不显示表格
        if (data.results.length === 0) {
            return;
        }

        // 显示表格
        resultsTable.style.display = 'table';
        
        // 排序结果（开放端口优先）
        const sortedResults = [...data.results].sort((a, b) => {
            // 首先按状态排序（开放 > 过滤 > 关闭）
            const stateOrder = { 'open': 0, 'filtered': 1, 'closed': 2 };
            if (stateOrder[a.state] !== stateOrder[b.state]) {
                return stateOrder[a.state] - stateOrder[b.state];
            }
            // 然后按端口号排序
            return a.port - b.port;
        });

        // 清空表格
        resultsBody.innerHTML = '';
        
        // 添加行
        sortedResults.forEach(result => {
            if (result.state === 'closed' && openPorts > 0) {
                return; // 如果有开放端口，不显示关闭的端口
            }
            
            const row = document.createElement('tr');
            
            // 端口
            const portCell = document.createElement('td');
            portCell.textContent = result.port;
            row.appendChild(portCell);
            
            // 状态
            const stateCell = document.createElement('td');
            let stateText = '';
            if (result.state === 'open') {
                stateText = '开放';
                stateCell.className = 'open';
            } else if (result.state === 'closed') {
                stateText = '关闭';
                stateCell.className = 'closed';
            } else if (result.state === 'filtered') {
                stateText = '被过滤';
                stateCell.className = 'filtered';
            }
            stateCell.textContent = stateText;
            row.appendChild(stateCell);
            
            // 服务
            const serviceCell = document.createElement('td');
            serviceCell.textContent = result.service_name || '-';
            row.appendChild(serviceCell);
            
            // 版本
            const versionCell = document.createElement('td');
            if (result.service && result.service.version) {
                versionCell.textContent = result.service.version;
            } else {
                versionCell.textContent = '-';
            }
            row.appendChild(versionCell);
            
            resultsBody.appendChild(row);
        });
    }
}); 