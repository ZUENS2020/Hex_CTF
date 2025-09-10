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
    btn.textContent = 'Copy';
    btn.className = 'copy-btn';
    btn.onclick = () => {
        navigator.clipboard.writeText(textToCopy).then(() => {
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
        });
    };
    element.appendChild(btn);
}

// --- Rendering Functions ---

function renderOverview(data) {
    const content = `
Filename: ${escapeHTML(data.filename)}
File Size: ${data.filesize} bytes
Overall Entropy: ${data.overall_entropy.toFixed(4)}
MD5: ${data.file_digest.md5}
SHA1: ${data.file_digest.sha1}
SHA256: ${data.file_digest.sha256}
<hr>
Magic Bytes Type: ${escapeHTML(data.file_type_analysis.magic_bytes_type)}
Extension: ${escapeHTML(data.file_type_analysis.extension)}
libmagic Type: ${escapeHTML(data.file_type_analysis.libmagic_type)}
Type Mismatch: <span class="${data.file_type_analysis.type_mismatch ? 'severity-WARNING' : ''}">${data.file_type_analysis.type_mismatch}</span>
    `;
    document.getElementById('overview-content').innerHTML = content;
}

function renderFindings(findings) {
    const container = document.getElementById('findings-content');
    container.innerHTML = '';
    if (!findings || findings.length === 0) {
        container.textContent = 'No significant findings.';
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
            p.innerHTML = `<strong>Value:</strong> <code>${valueText}</code>`;
            addCopyButton(p, String(finding.value));
            findingHTML += p.outerHTML;
        }
        if (finding.hint) {
            findingHTML += `<p><strong>Hint:</strong> <em>${escapeHTML(finding.hint)}</em></p>`;
        }
        el.innerHTML = findingHTML;
        container.appendChild(el);
    });
}

function renderAIAnalysis(ai) {
    const container = document.getElementById('ai-analysis-content');
    if (!ai || ai.error) {
        container.innerHTML = `<p><strong>AI Analysis Status:</strong> ${ai ? escapeHTML(ai.error) : 'Not performed.'}</p>`;
        return;
    }
    let content = `<p><strong>Model:</strong> ${escapeHTML(ai.model)}</p>`;
    content += '<strong>Response:</strong>';
    const responseBlock = document.createElement('blockquote');
    responseBlock.textContent = ai.response_received;
    addCopyButton(responseBlock, ai.response_received)
    container.innerHTML = content;
    container.appendChild(responseBlock);
}

function renderHexPreview(preview) {
    const container = document.getElementById('hex-content');
    let content = '<h4>File Head</h4><div class="hex-grid">';
    content += `<div class="offset">Offset</div><div>Hex Data</div>`;
    content += `<div class="hex-data">${escapeHTML(preview.head)}</div>`;
    content += `<div class="ascii-data">${escapeHTML(preview.head_ascii)}</div>`;
    content += '</div>';

    if (preview.tail) {
        content += '<h4>File Tail</h4><div class="hex-grid">';
        content += `<div class="offset">Offset</div><div>Hex Data</div>`;
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
        list.innerHTML = '<li>No printable strings found.</li>';
        return;
    }
    strings.forEach(s => {
        const li = document.createElement('li');
        if (s.is_flag) {
            li.className = 'is-flag';
        }
        const text = `Offset: 0x${s.offset.toString(16).padStart(8, '0')} | Content: ${escapeHTML(s.content)}`;
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
        errorDisplay.textContent = 'Please select a file first.';
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
        renderAIAnalysis(data.ai_analysis_results);
        renderHexPreview(data.hex_ascii_preview);
        renderStrings(data.extracted_strings);

        resultsContainer.classList.remove('hidden');

    } catch (error) {
        errorDisplay.textContent = `Analysis failed: ${error.message}`;
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
        dropZone.querySelector('p').textContent = `File selected: ${fileInput.files[0].name}`;
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
        dropZone.querySelector('p').textContent = `File selected: ${e.dataTransfer.files[0].name}`;
    }
});
stringFilter.addEventListener('keyup', handleFileFilter);
