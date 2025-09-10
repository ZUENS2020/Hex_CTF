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
        if (finding.recommended_tool) {
            const tool = finding.recommended_tool;
            findingHTML += `<p class="tool-recommendation"><strong>🔧 推荐工具:</strong> <code>${escapeHTML(tool.name)}</code> &mdash; <em>${escapeHTML(tool.description)}</em></p>`;
        }
        el.innerHTML = findingHTML;
        container.appendChild(el);
    });
}

function renderLsbAnalysis(lsb) {
    const container = document.getElementById('lsb-content');
    container.innerHTML = '';
    if (!lsb) {
        container.innerHTML = '<p>未在此图像中执行或检测到LSB隐写分析。</p>';
        return;
    }

    if (lsb.error) {
        container.innerHTML = `<p>LSB分析错误: ${escapeHTML(lsb.error)}</p>`;
        return;
    }

    let content = '<h3>LSB层分析结果</h3>';
    if (lsb.findings && lsb.findings.length > 0) {
        lsb.findings.forEach(finding => {
            content += `<div class="finding severity-${finding.severity}">`;
            content += `<div class="finding-title">${escapeHTML(finding.type)} <span class="severity severity-${finding.severity}">${escapeHTML(finding.severity)}</span></div>`;
            content += `<p>${escapeHTML(finding.description)}</p>`;
            if (finding.value) {
                content += `<p><strong>值:</strong> <code>${escapeHTML(String(finding.value))}</code></p>`;
            }
            content += '</div>';
        });
    } else {
        content += '<p>在LSB层中未发现特定线索。</p>';
    }

    if (lsb.base64_data) {
        content += `<hr><button id="download-lsb-btn">下载提取的数据 (二进制)</button>`;
    }
    container.innerHTML = content;

    const downloadBtn = document.getElementById('download-lsb-btn');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            const byteCharacters = atob(lsb.base64_data);
            const byteNumbers = new Array(byteCharacters.length);
            for (let i = 0; i < byteCharacters.length; i++) {
                byteNumbers[i] = byteCharacters.charCodeAt(i);
            }
            const byteArray = new Uint8Array(byteNumbers);
            const blob = new Blob([byteArray], {type: 'application/octet-stream'});
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = 'lsb_extracted_data.bin';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        });
    }
}

function renderFileStructure(structure) {
    const container = document.getElementById('structure-content');
    container.innerHTML = '';
    if (!structure || structure.length === 0) {
        container.innerHTML = '<p>此文件类型没有可展示的内部结构，或文件为空。</p>';
        return;
    }

    const table = document.createElement('table');
    table.className = 'structure-table';
    const thead = document.createElement('thead');
    const tbody = document.createElement('tbody');

    // Dynamically create headers based on the type of the first item
    const headers = Object.keys(structure[0]);
    const trHead = document.createElement('tr');
    headers.forEach(header => {
        const th = document.createElement('th');
        th.textContent = escapeHTML(header);
        trHead.appendChild(th);
    });
    thead.appendChild(trHead);

    // Create rows
    structure.forEach(item => {
        const tr = document.createElement('tr');
        headers.forEach(header => {
            const td = document.createElement('td');
            td.textContent = escapeHTML(item[header]);
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });

    table.appendChild(thead);
    table.appendChild(tbody);
    container.appendChild(table);
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
        renderFileStructure(data.file_structure);
        renderLsbAnalysis(data.lsb_analysis);
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
