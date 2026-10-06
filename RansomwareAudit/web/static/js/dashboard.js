// ---- auth + safety helpers ----
// The server prints a URL like http://localhost:5001/#token=XYZ. The token sits in
// the URL fragment (never sent to the server or logged), gets saved for this tab,
// then removed from the address bar.
(function captureToken() {
    const m = location.hash.match(/token=([^&]+)/);
    if (m) {
        try { sessionStorage.setItem('ra_token', decodeURIComponent(m[1])); } catch (e) {}
        window.RA_TOKEN = decodeURIComponent(m[1]);
        history.replaceState(null, '', location.pathname);
    }
})();

function getToken() {
    if (window.RA_TOKEN) return window.RA_TOKEN;
    try { return sessionStorage.getItem('ra_token') || ''; } catch (e) { return ''; }
}

function api(url, options = {}) {
    const headers = Object.assign({'X-Auth-Token': getToken()}, options.headers || {});
    return fetch(url, Object.assign({}, options, {headers})).then(r => {
        if (r.status === 401) {
            alert('Not authorized. Open the dashboard using the link printed in the terminal.');
        }
        return r;
    });
}

// Escape anything that came from the file system before putting it in HTML,
// so a file named <img src=x onerror=...> can't run script in the dashboard.
function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

let riskChart, activityChart;

document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', function(e) {
        e.preventDefault();
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
        this.classList.add('active');
        
        const section = this.dataset.section;
        document.querySelectorAll('.content-section').forEach(sec => sec.classList.remove('active'));
        document.getElementById(`${section}-section`).classList.add('active');
        
        const titles = {
            'overview': 'System Overview',
            'scanner': 'New Scan',
            'history': 'Scan History',
            'quarantine': 'Quarantine Management',
            'backups': 'Backup Management',
            'ml': 'Machine Learning'
        };
        document.getElementById('page-title').textContent = titles[section];
        
        if (section === 'overview') loadOverview();
        if (section === 'history') loadHistory();
        if (section === 'quarantine') loadQuarantine();
        if (section === 'backups') loadBackups();
        if (section === 'ml') loadMLStatus();
    });
});

async function loadOverview() {
    const response = await api('/api/stats');
    const stats = await response.json();
    
    document.getElementById('total-scans').textContent = stats.total_scans;
    document.getElementById('total-files').textContent = stats.total_files_scanned.toLocaleString();
    document.getElementById('total-threats').textContent = stats.total_flagged;
    document.getElementById('quarantined-count').textContent = stats.quarantined_files;
    
    if (riskChart) riskChart.destroy();
    const ctx = document.getElementById('riskChart').getContext('2d');
    riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(stats.risk_distribution || {}).length > 0 ? Object.keys(stats.risk_distribution) : ['No Data'],
            datasets: [{
                data: Object.keys(stats.risk_distribution || {}).length > 0 ? Object.values(stats.risk_distribution) : [1],
                backgroundColor: ['#27ae60', '#f39c12', '#e74c3c', '#c0392b']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

async function startScan() {
    const path = document.getElementById('scan-path').value;
    const btn = document.getElementById('scan-btn-text');
    const progress = document.getElementById('scan-progress');
    const result = document.getElementById('scan-result');
    
    btn.textContent = 'Scanning...';
    progress.style.display = 'block';
    result.innerHTML = '';
    
    try {
        const response = await api('/api/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({path: path})
        });
        
        const data = await response.json();
        
        if (data.success) {
            const risk = data.result.risk_summary;
            result.className = `scan-result ${risk.risk_level === 'LOW' ? 'result-success' : 'result-danger'}`;
            result.innerHTML = `
                <h3>Scan Complete</h3>
                <p><strong>Risk Level:</strong> ${risk.risk_level}</p>
                <p><strong>Total Score:</strong> ${risk.total_score.toFixed(2)}</p>
                <p><strong>Files Scanned:</strong> ${data.result.statistics.total_files}</p>
                <p><strong>Flagged Files:</strong> ${data.result.statistics.high_risk_files}</p>
                ${risk.behavior_reasons.length ? `<ul>${risk.behavior_reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
                ${risk.flagged_files.length ? `<h4 style="margin-top:12px">Top flagged</h4><ol>${
                    risk.flagged_files.slice(0, 10).map(f =>
                        `<li><code>${esc(f.file)}</code> (score ${esc(f.score)}): ${esc(f.reasons.join('; '))}</li>`
                    ).join('')}</ol>` : ''}
            `;
            loadOverview();
        } else {
            result.className = 'scan-result result-danger';
            result.innerHTML = `<p>Error: ${esc(data.error)}</p>`;
        }
    } catch (error) {
        result.className = 'scan-result result-danger';
        result.innerHTML = `<p>Error: ${esc(error.message)}</p>`;
    }
    
    btn.textContent = 'Start Scan';
    progress.style.display = 'none';
}

async function loadHistory() {
    const response = await api('/api/scan-history');
    const scans = await response.json();
    
    const tbody = document.getElementById('history-tbody');
    tbody.innerHTML = scans.map(scan => `
        <tr>
            <td>${new Date(scan.timestamp).toLocaleString()}</td>
            <td>${esc(scan.scan_path)}</td>
            <td><span class="badge badge-${esc(scan.risk_level.toLowerCase())}">${esc(scan.risk_level)}</span></td>
            <td>${scan.total_score.toFixed(2)}</td>
            <td>${scan.files_scanned}</td>
            <td>${scan.flagged_files}</td>
        </tr>
    `).join('');
}

async function loadQuarantine() {
    const response = await api('/api/quarantine');
    const files = await response.json();
    
    const statsResponse = await api('/api/quarantine/stats');
    const stats = await statsResponse.json();
    
    document.getElementById('q-total').textContent = stats.total_quarantined;
    document.getElementById('q-size').textContent = stats.total_size_mb;
    
    const tbody = document.getElementById('quarantine-tbody');
    tbody.innerHTML = files.map(file => `
        <tr>
            <td>${esc(file.filename)}</td>
            <td>${esc(file.original_path)}</td>
            <td>${esc(new Date(file.timestamp).toLocaleString())}</td>
            <td>${esc((file.metadata || {}).score ?? '')}</td>
            <td>
                <button class="btn btn-sm btn-primary" data-qid="${esc(file.id)}">Restore</button>
            </td>
        </tr>
    `).join('');
    tbody.querySelectorAll('button[data-qid]').forEach(b =>
        b.addEventListener('click', () => restoreFile(b.dataset.qid)));
}

async function restoreFile(qid) {
    if (!confirm('Restore this file?')) return;
    
    const response = await api('/api/quarantine/restore', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: qid})
    });
    
    const data = await response.json();
    if (data.success) {
        alert('File restored successfully');
        loadQuarantine();
    } else {
        alert('Failed to restore: ' + (data.error || 'unknown error'));
    }
}

async function loadBackups() {
    const response = await api('/api/backups');
    const backups = await response.json();
    
    const container = document.getElementById('backup-list-container');
    container.innerHTML = backups.map(backup => `
        <div class="backup-item" style="padding: 15px; background: #f8f9fa; border-radius: 10px; margin-bottom: 10px;">
            <h4>${esc(backup.backup_name)}</h4>
            <p>Source: ${esc(backup.source_dir)}</p>
            <p>Created: ${new Date(backup.timestamp).toLocaleString()}</p>
            <p>Size: ${esc(backup.size_mb)} MB</p>
        </div>
    `).join('');
}

async function createBackup() {
    const source = document.getElementById('backup-source').value;
    const name = document.getElementById('backup-name').value;
    
    const response = await api('/api/backup/create', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({source: source, name: name || null})
    });
    
    const data = await response.json();
    if (data.success) {
        alert('Backup created successfully');
        loadBackups();
    } else {
        alert('Failed to create backup: ' + (data.error || 'unknown error'));
    }
}

async function loadMLStatus() {
    const response = await api('/api/ml/status');
    const status = await response.json();
    
    const container = document.getElementById('ml-status');
    container.innerHTML = `
        <div class="stat-card">
            <h3>Model Status</h3>
            <p><strong>Trained:</strong> ${status.trained ? 'Yes' : 'No'}</p>
            <p><strong>Available:</strong> ${status.available ? 'Yes' : 'No'}</p>
            ${status.trained ? `<p><strong>Training Sessions:</strong> ${status.training_sessions}</p>` : ''}
            ${status.trained ? `<p><strong>Features:</strong> ${esc(status.feature_names.join(', '))}</p>` : ''}
        </div>
    `;
}

loadOverview();
