// 确保所有资源都加载完成后再初始化
window.addEventListener('load', function() {
    console.log('页面完全加载，开始初始化复制功能...');
    
    // 确保Prism.js已完成高亮处理
    setTimeout(function() {
        // 更新所有复制按钮
        updateCopyButtons();
        
        // 初始化复制功能
        initializeClipboard();
    }, 500); // 给一点时间让Prism.js完成初始渲染
});

// 更新所有复制按钮的data-clipboard-text
function updateCopyButtons() {
    console.log('更新复制按钮内容...');
    
    document.querySelectorAll('.copy-btn').forEach(function(btn) {
        var codeBlock = btn.closest('.code-block');
        if (!codeBlock) {
            // 向上查找可能的代码块容器
            codeBlock = btn.parentElement;
            while (codeBlock && !codeBlock.querySelector('pre code') && codeBlock !== document.body) {
                codeBlock = codeBlock.parentElement;
            }
        }
        
        if (codeBlock) {
            var codeElement = codeBlock.querySelector('pre code');
            if (codeElement) {
                // 获取纯文本内容，避免HTML标签
                var textContent = codeElement.textContent.trim();
                btn.setAttribute('data-clipboard-text', textContent);
                console.log('已更新按钮内容: ', textContent.substring(0, 50) + '...');
            }
        }
    });
}

// 初始化复制功能
function initializeClipboard() {
    console.log('初始化ClipboardJS...');
    
    // 检查ClipboardJS是否已加载
    if (typeof ClipboardJS === 'undefined') {
        console.error('ClipboardJS库未加载！');
        return;
    }
    
    // 先尝试销毁任何现有的ClipboardJS实例，避免重复绑定
    try {
        if (window.clipboardInstance) {
            window.clipboardInstance.destroy();
        }
    } catch (err) {
        console.log('No existing clipboard instance to destroy');
    }
    
    // 初始化新的ClipboardJS实例
    try {
        window.clipboardInstance = new ClipboardJS('.copy-btn');
        
        // 复制成功效果
        window.clipboardInstance.on('success', function(e) {
            console.log('文本已复制:', e.text.substring(0, 50) + '...');
            var btn = e.trigger;
            var originalText = btn.innerHTML;
            btn.innerHTML = '<i class="far fa-check-circle"></i> 已复制';
            
            setTimeout(function() {
                btn.innerHTML = originalText;
            }, 2000);
            
            e.clearSelection();
        });
        
        // 复制失败效果
        window.clipboardInstance.on('error', function(e) {
            console.error('复制失败:', e);
            var btn = e.trigger;
            var originalText = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-exclamation-circle"></i> 复制失败';
            
            setTimeout(function() {
                btn.innerHTML = originalText;
            }, 2000);
        });
        
        console.log('ClipboardJS初始化成功！');
    } catch (err) {
        console.error('ClipboardJS初始化失败:', err);
    }
}

// 不要重新应用样式，只使用现有的样式
// 不要替换或覆盖已有的复制按钮绑定
// 这个文件只负责增强复制功能 