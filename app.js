/* ==========================================================================
   Intrusion Detection System (IDS) - Frontend JavaScript Controller
   ========================================================================== */

let streamEventSource = null;
let isStreaming = false;

// Chart Instances
let throughputChartInstance = null;
let livePieChartInstance = null;
let probabilityChartInstance = null;
let batchPieChartInstance = null;
let featureImportanceChartInstance = null;

// Live Stream Telemetry
let throughputLabels = [];
let throughputData = [];
let liveStats = { Normal: 0, DoS: 0, Probe: 0, BruteForce: 0 };

// Presets Data
const PRESETS = {
  normal: {
    duration: 12.5, protocol_type: 0, service: 0, src_bytes: 450, dst_bytes: 2300,
    flag: 0, wrong_fragment: 0, hot: 0, failed_logins: 0, count: 10, srv_count: 8,
    same_srv_rate: 0.95, diff_srv_rate: 0.05, dst_host_srv_count: 150, dst_host_same_srv_rate: 0.90
  },
  ddos: {
    duration: 0.001, protocol_type: 0, service: 0, src_bytes: 20, dst_bytes: 0,
    flag: 1, wrong_fragment: 0, hot: 0, failed_logins: 0, count: 450, srv_count: 420,
    same_srv_rate: 0.98, diff_srv_rate: 0.02, dst_host_srv_count: 5, dst_host_same_srv_rate: 0.15
  },
  probe: {
    duration: 0.05, protocol_type: 0, service: 5, src_bytes: 40, dst_bytes: 0,
    flag: 2, wrong_fragment: 0, hot: 0, failed_logins: 0, count: 250, srv_count: 2,
    same_srv_rate: 0.05, diff_srv_rate: 0.92, dst_host_srv_count: 10, dst_host_same_srv_rate: 0.08
  },
  bruteforce: {
    duration: 3.5, protocol_type: 0, service: 1, src_bytes: 350, dst_bytes: 450,
    flag: 0, wrong_fragment: 0, hot: 3, failed_logins: 5, count: 80, srv_count: 75,
    same_srv_rate: 0.90, diff_srv_rate: 0.08, dst_host_srv_count: 110, dst_host_same_srv_rate: 0.82
  }
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  fetchSystemStatus();
  initCharts();
  loadModelMetrics();
  loadAlertLogs();
  
  // Drag and Drop handlers for CSV dropzone
  const dropzone = document.getElementById('csv-dropzone');
  if (dropzone) {
    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
      }, false);
    });
    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
      }, false);
    });
    dropzone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;
      if (files.length) {
        handleFileUpload({ target: { files: files } });
      }
    });
  }
});

// Tab Switcher
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
  
  const selectedContent = document.getElementById(`tab-${tabId}`);
  if (selectedContent) {
    selectedContent.classList.add('active');
  }
  
  event.currentTarget.classList.add('active');

  // Trigger chart resize if switching tabs
  setTimeout(() => {
    if (tabId === 'live-monitor') {
      if (throughputChartInstance) throughputChartInstance.resize();
      if (livePieChartInstance) livePieChartInstance.resize();
    } else if (tabId === 'ai-analytics' && featureImportanceChartInstance) {
      featureImportanceChartInstance.resize();
    }
  }, 100);
}

// Fetch Status KPIs
async function fetchSystemStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    
    document.getElementById('kpi-total').innerText = data.total_scanned.toLocaleString();
    document.getElementById('kpi-threats').innerText = data.threats_detected.toLocaleString();
    document.getElementById('kpi-normal').innerText = data.normal_packets.toLocaleString();
    document.getElementById('kpi-accuracy').innerText = `${data.model_accuracy}%`;
    document.getElementById('kpi-threat-rate').innerText = `${data.threat_rate}% threat ratio`;
    document.getElementById('hdr-model-name').innerText = data.model_name;
  } catch (err) {
    console.error('Error fetching system status:', err);
  }
}

// Init Charts
function initCharts() {
  // Throughput Line Chart
  const ctxLine = document.getElementById('throughputChart').getContext('2d');
  throughputChartInstance = new Chart(ctxLine, {
    type: 'line',
    data: {
      labels: throughputLabels,
      datasets: [{
        label: 'Packets / sec',
        data: throughputData,
        borderColor: '#00f2fe',
        backgroundColor: 'rgba(0, 242, 254, 0.1)',
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointBackgroundColor: '#00f2fe'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
        y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' }, beginAtZero: true }
      },
      plugins: { legend: { display: false } }
    }
  });

  // Live Threat Pie Chart
  const ctxPie = document.getElementById('livePieChart').getContext('2d');
  livePieChartInstance = new Chart(ctxPie, {
    type: 'doughnut',
    data: {
      labels: ['Normal', 'DoS / DDoS', 'Port Scan', 'Brute Force'],
      datasets: [{
        data: [1, 0, 0, 0],
        backgroundColor: ['#00e676', '#ff1744', '#ff9100', '#d500f9'],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11 } } }
      }
    }
  });
}

// Live Stream Controller
function toggleLiveStream() {
  const btn = document.getElementById('btn-toggle-stream');
  const statusLbl = document.getElementById('stream-status-lbl');
  
  if (isStreaming) {
    // Stop Stream
    if (streamEventSource) streamEventSource.close();
    isStreaming = false;
    btn.innerHTML = '<i class="fa-solid fa-play"></i> Start Stream';
    btn.className = 'btn btn-primary';
    statusLbl.innerText = 'Stream Paused';
    statusLbl.style.color = '#ff9100';
  } else {
    // Start SSE Stream
    streamEventSource = new EventSource('/api/simulation/stream');
    isStreaming = true;
    btn.innerHTML = '<i class="fa-solid fa-pause"></i> Pause Stream';
    btn.className = 'btn btn-danger';
    statusLbl.innerText = 'LIVE STREAM MONITORING ACTIVE';
    statusLbl.style.color = '#00e676';
    
    const tbody = document.getElementById('live-stream-tbody');
    tbody.innerHTML = ''; // clear placeholder

    streamEventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const pred = data.prediction;
      const log = data.log;
      
      // Update KPIs
      document.getElementById('kpi-total').innerText = data.stats.total.toLocaleString();
      document.getElementById('kpi-threats').innerText = data.stats.threats.toLocaleString();
      document.getElementById('kpi-normal').innerText = data.stats.normal.toLocaleString();

      // Update Throughput Chart
      const timeStr = new Date().toLocaleTimeString();
      throughputLabels.push(timeStr);
      throughputData.push(Math.floor(Math.random() * 40) + 60);
      if (throughputLabels.length > 15) {
        throughputLabels.shift();
        throughputData.shift();
      }
      throughputChartInstance.update();

      // Update Pie Stats
      if (pred.label_id === 0) liveStats.Normal++;
      else if (pred.label_id === 1) liveStats.DoS++;
      else if (pred.label_id === 2) liveStats.Probe++;
      else if (pred.label_id === 3) liveStats.BruteForce++;

      livePieChartInstance.data.datasets[0].data = [
        liveStats.Normal, liveStats.DoS, liveStats.Probe, liveStats.BruteForce
      ];
      livePieChartInstance.update();

      // Insert Row into Table
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="font-mono">${log.timestamp}</td>
        <td class="font-mono">${log.src_ip}</td>
        <td class="font-mono">${log.dst_ip}</td>
        <td>${pred.protocol_str}</td>
        <td>${pred.service_str}</td>
        <td style="font-weight: 600; color: ${pred.color};">${pred.prediction}</td>
        <td><span class="badge ${pred.badge}">${pred.severity}</span></td>
        <td class="font-mono">${pred.confidence}%</td>
      `;
      tbody.insertBefore(tr, tbody.firstChild);
      
      if (tbody.children.length > 50) {
        tbody.removeChild(tbody.lastChild);
      }
    };

    streamEventSource.onerror = (err) => {
      console.error('SSE Error:', err);
    };
  }
}

// Preset Loader for Single Inspector
function loadPreset(key) {
  const data = PRESETS[key];
  if (!data) return;

  for (const col in data) {
    const el = document.getElementById(col);
    if (el) {
      el.value = data[col];
    }
  }

  // Trigger form submit to visualize preset
  document.getElementById('single-packet-form').dispatchEvent(new Event('submit'));
}

// Single Packet Predict Handler
async function handleSinglePredict(e) {
  e.preventDefault();
  
  const payload = {};
  const fields = [
    'duration', 'protocol_type', 'service', 'src_bytes', 'dst_bytes', 
    'flag', 'wrong_fragment', 'hot', 'failed_logins', 'count', 
    'srv_count', 'same_srv_rate', 'diff_srv_rate', 'dst_host_srv_count', 
    'dst_host_same_srv_rate'
  ];
  
  fields.forEach(f => {
    payload[f] = parseFloat(document.getElementById(f).value || 0);
  });

  try {
    const res = await fetch('/api/predict/single', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const result = await res.json();
    
    if (result.status === 'success') {
      const d = result.data;
      
      // Update UI Result Card
      const ring = document.getElementById('result-status-ring');
      const icon = document.getElementById('result-icon');
      const title = document.getElementById('result-title');
      const badge = document.getElementById('result-severity-badge');
      const confLbl = document.getElementById('result-confidence-lbl');
      const confBar = document.getElementById('result-confidence-bar');
      const mit = document.getElementById('result-mitigation-text');

      title.innerText = d.prediction;
      confLbl.innerText = `${d.confidence}%`;
      confBar.style.width = `${d.confidence}%`;
      confBar.style.backgroundColor = d.color;
      mit.innerText = d.mitigation;
      
      badge.innerText = d.severity;
      badge.className = `badge ${d.badge}`;

      ring.style.backgroundColor = `${d.color}20`;
      ring.style.borderColor = d.color;
      ring.style.color = d.color;
      
      if (d.label_id === 0) icon.className = 'fa-solid fa-shield-check';
      else if (d.label_id === 1) icon.className = 'fa-solid fa-fire-flame-curved';
      else if (d.label_id === 2) icon.className = 'fa-solid fa-radar';
      else icon.className = 'fa-solid fa-user-lock';

      // Update Probability Donut Chart
      updateProbabilityChart(d.probabilities);
      
      // Refresh KPIs & Logs
      fetchSystemStatus();
      loadAlertLogs();
    }
  } catch (err) {
    console.error('Error single prediction:', err);
  }
}

// Probability Donut Chart
function updateProbabilityChart(probData) {
  const ctx = document.getElementById('probabilityChart').getContext('2d');
  
  if (probabilityChartInstance) {
    probabilityChartInstance.destroy();
  }

  const labels = Object.keys(probData);
  const values = Object.values(probData);

  probabilityChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Probability (%)',
        data: values,
        backgroundColor: ['#00e676', '#ff1744', '#ff9100', '#d500f9'],
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { min: 0, max: 100, ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { display: false } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

// File Upload Handler for Batch CSV
async function handleFileUpload(e) {
  const files = e.target.files;
  if (!files || !files.length) return;

  const file = files[0];
  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/predict/batch', {
      method: 'POST',
      body: formData
    });
    const result = await res.json();

    if (result.status === 'success') {
      const data = result.data;
      document.getElementById('batch-results-container').style.display = 'block';

      // Render summary
      document.getElementById('batch-sum-total').innerText = data.summary.total_packets.toLocaleString();
      document.getElementById('batch-sum-malicious').innerText = data.summary.malicious_count.toLocaleString();
      document.getElementById('batch-sum-clean').innerText = data.summary.normal_count.toLocaleString();

      // Render Pie
      renderBatchPie(data.summary);

      // Render Table
      const tbody = document.getElementById('batch-results-tbody');
      tbody.innerHTML = '';
      
      data.predictions.slice(0, 100).forEach(row => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="font-mono">#${row.row_index}</td>
          <td style="font-weight: 600; color: ${row.color};">${row.prediction}</td>
          <td><span class="badge ${getBadgeClass(row.severity)}">${row.severity}</span></td>
          <td class="font-mono">${row.confidence}%</td>
          <td class="font-mono">${row.src_bytes}</td>
          <td class="font-mono">${row.dst_bytes}</td>
          <td class="font-mono">${row.duration}s</td>
          <td class="font-mono">${row.count}</td>
        `;
        tbody.appendChild(tr);
      });

      fetchSystemStatus();
      loadAlertLogs();
    } else {
      alert('Batch upload error: ' + result.message);
    }
  } catch (err) {
    console.error('File upload failed:', err);
  }
}

function getBadgeClass(severity) {
  if (severity === 'SAFE') return 'badge-success';
  if (severity === 'HIGH') return 'badge-warning';
  if (severity === 'CRITICAL') return 'badge-danger';
  return 'badge-purple';
}

function renderBatchPie(summary) {
  const ctx = document.getElementById('batchPieChart').getContext('2d');
  if (batchPieChartInstance) batchPieChartInstance.destroy();

  batchPieChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Clean', 'DoS/DDoS', 'Port Scan', 'Brute Force'],
      datasets: [{
        data: [summary.normal_count, summary.dos_count, summary.probe_count, summary.brute_force_count],
        backgroundColor: ['#00e676', '#ff1744', '#ff9100', '#d500f9'],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'right', labels: { color: '#94a3b8' } } }
    }
  });
}

// Load Model Analytics & Metrics
async function loadModelMetrics() {
  try {
    const res = await fetch('/api/model/metrics');
    const data = await res.json();

    document.getElementById('m-precision').innerText = `${data.precision}%`;
    document.getElementById('m-recall').innerText = `${data.recall}%`;
    document.getElementById('m-f1').innerText = `${data.f1_score}%`;
    document.getElementById('m-samples').innerText = data.total_test_samples.toLocaleString();

    // Feature Importances Bar Chart
    renderFeatureImportanceChart(data.feature_importances);

    // Confusion Matrix Grid
    renderConfusionMatrix(data.confusion_matrix);
  } catch (err) {
    console.error('Error loading metrics:', err);
  }
}

function renderFeatureImportanceChart(importances) {
  const ctx = document.getElementById('featureImportanceChart').getContext('2d');
  if (featureImportanceChartInstance) featureImportanceChartInstance.destroy();

  const labels = importances.map(i => i.feature);
  const values = importances.map(i => i.importance);

  featureImportanceChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Importance %',
        data: values,
        backgroundColor: 'rgba(0, 242, 254, 0.65)',
        borderColor: '#00f2fe',
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { display: false } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

function renderConfusionMatrix(matrix) {
  const grid = document.getElementById('confusion-matrix-grid');
  grid.innerHTML = '';
  
  const classNames = ['Normal', 'DoS', 'Probe', 'BruteForce'];
  
  for (let r = 0; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      const val = matrix[r][c];
      const isDiag = (r === c);
      const cell = document.createElement('div');
      cell.className = `matrix-cell ${isDiag ? 'highlight-diagonal' : ''}`;
      cell.innerHTML = `
        <div class="cell-value" style="color: ${isDiag ? '#00e676' : '#ff1744'};">${val}</div>
        <div class="cell-label">${classNames[r]} → ${classNames[c]}</div>
      `;
      grid.appendChild(cell);
    }
  }
}

// Retrain Model Handler
async function handleRetrain(e) {
  e.preventDefault();
  const btn = document.getElementById('btn-retrain');
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Training...';

  const n_estimators = parseInt(document.getElementById('n_estimators').value || 100);
  const max_depth = parseInt(document.getElementById('max_depth').value || 16);

  try {
    const res = await fetch('/api/model/retrain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ n_estimators, max_depth })
    });
    const result = await res.json();
    
    if (result.status === 'success') {
      alert(`Model successfully re-trained! Accuracy: ${result.metrics.accuracy}%`);
      loadModelMetrics();
      fetchSystemStatus();
    } else {
      alert('Error re-training model: ' + result.message);
    }
  } catch (err) {
    console.error('Error re-training:', err);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Re-Train Classifier';
  }
}

// Load Intrusion Alert Logs Table
async function loadAlertLogs() {
  const filter = document.getElementById('log-severity-filter')?.value || '';
  try {
    const res = await fetch(`/api/logs?severity=${filter}&limit=100`);
    const data = await res.json();
    
    const tbody = document.getElementById('logs-tbody');
    if (!data.logs || !data.logs.length) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" style="text-align: center; color: var(--text-dim); padding: 2rem;">
            No alert logs found for this filter.
          </td>
        </tr>`;
      return;
    }

    tbody.innerHTML = '';
    data.logs.forEach(log => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="font-mono">${log.id}</td>
        <td class="font-mono">${log.timestamp}</td>
        <td class="font-mono">${log.src_ip}</td>
        <td class="font-mono">${log.dst_ip}</td>
        <td style="font-weight: 600; color: ${log.color};">${log.threat}</td>
        <td><span class="badge ${getBadgeClass(log.severity)}">${log.severity}</span></td>
        <td class="font-mono">${log.confidence}%</td>
        <td style="font-size: 0.78rem; color: var(--text-muted); max-width: 280px; white-space: normal;">${log.mitigation}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading logs:', err);
  }
}
