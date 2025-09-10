// --- Configuration ---
const API_BASE_URL = 'http://localhost:5000';

// --- DOM Elements ---
const uploadForm = document.getElementById('upload-form');
const fileInput = document.getElementById('file-input');
const dropZone = document.getElementById('drop-zone');
const loadingIndicator = document.getElementById('loading-indicator');
const errorDisplay = document.getElementById('error-display');
const resultsContainer = document.getElementById('results-container');
const stringFilter = document.getElementById('string-filter');
const settingsBtn = document.getElementById('settings-btn');
const settingsModal = document.getElementById('settings-modal');
const closeModalBtn = document.querySelector('.close-btn');
const aiSettingsForm = document.getElementById('ai-settings-form');

// --- Utility Functions ---
function escapeHTML(str) {
    const p = document.createElement('p');
    p.appendChild(document.createTextNode(str));
    return p.innerHTML;
}

function addCopyButton(element, textToCopy) {
    const btn = document.createElement('button');
    btn.textContent = '复制';
    btn.className = 'copy-btn';
    btn.onclick = () => {
        navigator.clipboard.writeText(textToCopy).then(() => {
            btn.textContent = '已复制!';
            setTimeout(() => { btn.textContent = '复制'; }, 2000);
        });
    };
    element.appendChild(btn);
}

// --- Rendering Functions ---

function renderOverview(data) {
    const content = `
文件名: ${escapeHTML(data.filename)}
文件大小: ${data.filesize} 字节
整体熵值: ${data.overall_entropy.toFixed(4)}
MD5: ${data.file_digest.md5}
SHA1: ${data.file_digest.sha1}
SHA256: ${data.file_digest.sha256}
<hr>
Magic字节类型: ${escapeHTML(data.file_type_analysis.magic_bytes_type)}
扩展名: ${escapeHTML(data.file_type_analysis.extension)}
libmagic类型: ${escapeHTML(data.file_type_analysis.libmagic_type)}
类型不匹配: <span class="${data.file_type_analysis.type_mismatch ? 'severity-WARNING' : ''}">${data.file_type_analysis.type_mismatch}</span>
    `;
    document.getElementById('overview-content').innerHTML = content;
}

function renderFindings(findings) {
    const container = document.getElementById('findings-content');
    container.innerHTML = '';
    if (!findings || findings.length === 0) {
        container.textContent = '无重要发现。';
        return;
    }
    findings.forEach(finding => {
        const el = document.createElement('div');
        el.className = `finding severity-${finding.severity}`;
        let findingHTML = `<div class="finding-title">${escapeHTML(finding.type)} <span class="severity severity-${finding.severity}">${escapeHTML(finding.severity)}</span></div>`;
        findingHTML += `<p>${escapeHTML(finding.description)}</p>`;
        if (finding.value) {
            const valueText = escapeHTML(String(finding.value));
            const p = document.createElement('p');
            p.innerHTML = `<strong>值:</strong> <code>${valueText}</code>`;
            addCopyButton(p, String(finding.value));
            findingHTML += p.outerHTML;
        }
        if (finding.hint) {
            findingHTML += `<p><strong>提示:</strong> <em>${escapeHTML(finding.hint)}</em></p>`;
        }
        el.innerHTML = findingHTML;
        container.appendChild(el);
    });
}

function renderAIAnalysis(ai) {
    const container = document.getElementById('ai-analysis-content');
    if (!ai || ai.error) {
        container.innerHTML = `<p><strong>AI分析状态:</strong> ${ai ? escapeHTML(ai.error) : '未执行。'}</p>`;
        return;
    }
    let content = `<p><strong>模型:</strong> ${escapeHTML(ai.model)}</p>`;
    content += '<strong>响应:</strong>';
    const responseBlock = document.createElement('blockquote');
    responseBlock.textContent = ai.response_received;
    addCopyButton(responseBlock, ai.response_received)
    container.innerHTML = content;
    container.appendChild(responseBlock);
}

function renderHexPreview(preview) {
    const container = document.getElementById('hex-content');
    let content = '<h4>文件头</h4><div class="hex-grid">';
    content += `<div class="offset">偏移量</div><div>十六进制数据</div>`;
    content += `<div class="hex-data">${escapeHTML(preview.head)}</div>`;
    content += `<div class="ascii-data">${escapeHTML(preview.head_ascii)}</div>`;
    content += '</div>';

    if (preview.tail) {
        content += '<h4>文件尾</h4><div class="hex-grid">';
        content += `<div class="offset">偏移量</div><div>十六进制数据</div>`;
        content += `<div class="hex-data">${escapeHTML(preview.tail)}</div>`;
        content += `<div class="ascii-data">${escapeHTML(preview.tail_ascii)}</div>`;
        content += '</div>';
    }
    container.innerHTML = content;
}

function renderStrings(strings) {
    const list = document.getElementById('strings-list');
    list.innerHTML = '';
    if (!strings || strings.length === 0) {
        list.innerHTML = '<li>未找到可打印字符串。</li>';
        return;
    }
    strings.forEach(s => {
        const li = document.createElement('li');
        if (s.is_flag) {
            li.className = 'is-flag';
        }
        const text = `偏移量: 0x${s.offset.toString(16).padStart(8, '0')} | 内容: ${escapeHTML(s.content)}`;
        li.textContent = text;
        addCopyButton(li, s.content);
        list.appendChild(li);
    });
}

// --- Event Handlers ---

async function handleFormSubmit(event) {
    event.preventDefault();
    const file = fileInput.files[0];
    if (!file) {
        errorDisplay.textContent = '请先选择一个文件。';
        errorDisplay.classList.remove('hidden');
        return;
    }

    // Reset UI
    resultsContainer.classList.add('hidden');
    errorDisplay.classList.add('hidden');
    loadingIndicator.classList.remove('hidden');

    const formData = new FormData();
    formData.append('file', file);

    // Append AI settings from localStorage to the form data
    const savedConfig = localStorage.getItem('aiConfig');
    if (savedConfig) {
        const aiConfig = JSON.parse(savedConfig);
        formData.append('ai_url', aiConfig.url || '');
        formData.append('ai_key', aiConfig.key || '');
        formData.append('ai_model', aiConfig.model || '');
    }

    try {
        const response = await fetch(`${API_BASE_URL}/ctf_analyze`, {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.error || `HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();

        // Render all results
        renderOverview(data);
        renderFindings(data.findings);
        renderAIAnalysis(data.ai_analysis_results);
        renderHexPreview(data.hex_ascii_preview);
        renderStrings(data.extracted_strings);

        resultsContainer.classList.remove('hidden');

    } catch (error) {
        errorDisplay.textContent = `分析失败: ${error.message}`;
        errorDisplay.classList.remove('hidden');
    } finally {
        loadingIndicator.classList.add('hidden');
    }
}

function handleFileFilter() {
    const filterText = stringFilter.value.toLowerCase();
    const items = document.querySelectorAll('#strings-list li');
    items.forEach(item => {
        const text = item.textContent.toLowerCase();
        if (text.includes(filterText)) {
            item.style.display = '';
        } else {
            item.style.display = 'none';
        }
    });
}

// --- Initial Setup ---
uploadForm.addEventListener('submit', handleFormSubmit);
dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
        dropZone.querySelector('p').textContent = `已选择文件: ${fileInput.files[0].name}`;
    }
});

// Drag and drop listeners
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        dropZone.querySelector('p').textContent = `已选择文件: ${e.dataTransfer.files[0].name}`;
    }
});
stringFilter.addEventListener('keyup', handleFileFilter);

// --- Settings Modal Logic ---
function saveAiSettings() {
    const aiConfig = {
        url: document.getElementById('ai-url').value,
        key: document.getElementById('ai-key').value,
        model: document.getElementById('ai-model').value,
    };
    localStorage.setItem('aiConfig', JSON.stringify(aiConfig));
    alert('AI 设置已保存！');
    settingsModal.classList.add('hidden');
}

function loadAiSettings() {
    const savedConfig = localStorage.getItem('aiConfig');
    if (savedConfig) {
        const aiConfig = JSON.parse(savedConfig);
        document.getElementById('ai-url').value = aiConfig.url || '';
        document.getElementById('ai-key').value = aiConfig.key || '';
        document.getElementById('ai-model').value = aiConfig.model || '';
    }
}

settingsBtn.addEventListener('click', () => settingsModal.classList.remove('hidden'));
closeModalBtn.addEventListener('click', () => settingsModal.classList.add('hidden'));
aiSettingsForm.addEventListener('submit', (e) => {
    e.preventDefault();
    saveAiSettings();
});
window.addEventListener('click', (e) => {
    if (e.target === settingsModal) {
        settingsModal.classList.add('hidden');
    }
});

// Load settings on page load
document.addEventListener('DOMContentLoaded', loadAiSettings);

// --- Tab Switching Logic ---
const tabNav = document.querySelector('.tab-nav');
tabNav.addEventListener('click', (e) => {
    if (e.target && e.target.classList.contains('tab-link')) {
        // Remove active class from all tabs and panes
        document.querySelectorAll('.tab-link').forEach(tab => tab.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));

        // Add active class to the clicked tab
        e.target.classList.add('active');

        // Add active class to the corresponding pane
        const tabId = e.target.getAttribute('data-tab');
        document.getElementById(tabId).classList.add('active');
    }
});
