document.addEventListener("DOMContentLoaded", () => {
    // 1. Navigation & Tabs Switch
    const navItems = document.querySelectorAll(".nav-item");
    const tabContents = document.querySelectorAll(".tab-content");
    const viewTitle = document.getElementById("current-view-title");
    const viewSubtitle = document.getElementById("current-view-subtitle");

    const tabTitles = {
        "dashboard": { title: "SOC Overview Dashboard", subtitle: "Real-time threat monitoring and network traffic classification" },
        "alerts": { title: "Security Alerts Log", subtitle: "Real-time threat log auditing and firewall status controls" },
        "analyze": { title: "Traffic Analyzer", subtitle: "Inspect raw network connections with Random Forest threat classifier" },
        "performance": { title: "Model Performance Dashboard", subtitle: "Evaluate classifier accuracy, confusion matrix, features, and model metrics" },
        "pcap": { title: "PCAP Packet Analyzer", subtitle: "Upload and analyze raw packet captures using Scapy and Random Forest threat model" }
    };

    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const tabId = item.getAttribute("data-tab");
            
            // Set active class on nav
            navItems.forEach(nav => nav.classList.remove("active"));
            item.classList.add("active");
            
            // Switch tabs visibility
            tabContents.forEach(content => {
                if (content.id === `tab-${tabId}`) {
                    content.classList.remove("hidden");
                } else {
                    content.classList.add("hidden");
                }
            });
            
            // Update Title
            if (tabTitles[tabId]) {
                viewTitle.textContent = tabTitles[tabId].title;
                viewSubtitle.textContent = tabTitles[tabId].subtitle;
            }

            // Trigger performance tab initialization
            if (tabId === "performance") {
                initPerformanceTab();
            }
            
            // Trigger pcap tab initialization
            if (tabId === "pcap") {
                initPcapTab();
            }
        });
    });

    // 2. Real-time Clock display
    function updateClock() {
        const timeDisplay = document.getElementById("time-display");
        if (timeDisplay) {
            const now = new Date();
            const year = now.getFullYear();
            const month = String(now.getMonth() + 1).padStart(2, '0');
            const day = String(now.getDate()).padStart(2, '0');
            const hours = String(now.getHours()).padStart(2, '0');
            const minutes = String(now.getMinutes()).padStart(2, '0');
            const seconds = String(now.getSeconds()).padStart(2, '0');
            timeDisplay.textContent = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
        }
    }
    setInterval(updateClock, 1000);
    updateClock();

    // 3. Initialize Chart.js
    const ctxCategory = document.getElementById('categoryChart').getContext('2d');
    const categoryChart = new Chart(ctxCategory, {
        type: 'doughnut',
        data: {
            labels: ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    '#10b981', // Normal
                    '#e11d48', // DoS
                    '#f59e0b', // Probe
                    '#c084fc', // R2L
                    '#f472b6'  // U2R
                ],
                borderWidth: 1,
                borderColor: '#1e293b'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { family: 'Outfit', size: 12 } }
                }
            }
        }
    });

    const ctxTrend = document.getElementById('trendChart').getContext('2d');
    const trendChart = new Chart(ctxTrend, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Normal Traffic',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.05)',
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2
                },
                {
                    label: 'Threat Alerts',
                    data: [],
                    borderColor: '#e11d48',
                    backgroundColor: 'rgba(225, 29, 72, 0.05)',
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { family: 'Outfit', size: 12 } }
                }
            },
            scales: {
                x: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#94a3b8' } },
                y: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#94a3b8' } }
            }
        }
    });

    // 4. Model Health Check on Load
    function checkModelHealth() {
        const modelText = document.getElementById("model-status-text");
        fetch("/health")
            .then(res => res.json())
            .then(data => {
                if (data.status === "healthy" && data.model_loaded) {
                    modelText.textContent = "RF Model Online";
                    modelText.style.color = "#10b981";
                } else {
                    modelText.textContent = "Asset Load Error";
                    modelText.style.color = "#e11d48";
                }
            })
            .catch(err => {
                modelText.textContent = "Offline";
                modelText.style.color = "#94a3b8";
            });
    }
    checkModelHealth();

    // 5. Mock SOC traffic metrics & stream simulator
    let totalPackets = 0;
    let totalThreats = 0;
    let threatDistribution = { normal: 0, dos: 0, probe: 0, r2l: 0, u2r: 0 };
    
    // Recent logs cache
    const recentAlertsLog = [];
    const trendTimeLabels = [];
    const trendNormalData = [];
    const trendThreatData = [];

    // Alert Prioritization Engine Cache & Scoring (Phase 6)
    let prioritizedQueue = [];

    function enrichAlertIndicators(alert) {
        if (alert.category === 'DoS') {
            alert.count = alert.count || (Math.random() > 0.5 ? Math.floor(Math.random() * 100) + 160 : Math.floor(Math.random() * 100));
            alert.wrong_fragment = alert.wrong_fragment || (Math.random() > 0.7 ? Math.floor(Math.random() * 3) + 1 : 0);
        } else if (alert.category === 'Probe') {
            alert.count = alert.count || Math.floor(Math.random() * 30);
            alert.hot = alert.hot || (Math.random() > 0.8 ? Math.floor(Math.random() * 2) + 1 : 0);
        } else if (alert.category === 'R2L') {
            alert.num_failed_logins = alert.num_failed_logins || (Math.random() > 0.3 ? 85 : Math.floor(Math.random() * 10) + 1);
            alert.hot = alert.hot || (Math.random() > 0.5 ? Math.floor(Math.random() * 4) + 1 : 0);
        } else if (alert.category === 'U2R') {
            alert.root_shell = alert.root_shell || 1;
            alert.su_attempted = alert.su_attempted || (Math.random() > 0.5 ? 1 : 0);
        }
        return alert;
    }

    function calculatePriority(alert) {
        if (alert.category === 'Normal') {
            return {
                score: 0,
                level: 'Low',
                reason: 'Benign network connection.',
                action: 'No mitigation required.'
            };
        }
        
        const baseScores = {
            'DoS': 45,
            'Probe': 60,
            'R2L': 80,
            'U2R': 95
        };
        
        let score = baseScores[alert.category] || 50;
        const reasons = [];
        
        // 1. Failed Logins Trigger
        const failedLogins = alert.num_failed_logins || 0;
        if (failedLogins > 0) {
            const boost = Math.min(failedLogins * 5, 20);
            score += boost;
            reasons.push(`${failedLogins} failed login attempt(s)`);
        }
        
        // 2. Privilege Escalation Triggers
        const rootShell = alert.root_shell || 0;
        const suAttempted = alert.su_attempted || 0;
        if (rootShell === 1 || suAttempted > 0) {
            score += 15;
            reasons.push("unauthorized root shell access");
        }
        
        // 3. Connection Anomalies
        const hot = alert.hot || 0;
        if (hot > 2) {
            score += 10;
            reasons.push("suspicious access flags triggered");
        }
        
        const wrongFrag = alert.wrong_fragment || 0;
        if (wrongFrag > 0) {
            score += 12;
            reasons.push(`malformed packet fragments (${wrongFrag})`);
        }
        
        // 4. Volumetric Flooding
        const count = alert.count || 0;
        if (alert.category === 'DoS' && count > 150) {
            score += 10;
            reasons.push(`high frequency packet flood (${count} same host connections)`);
        }
        
        // Weight score with confidence
        score = score * (0.8 + 0.2 * alert.confidence);
        score = Math.max(Math.min(Math.round(score), 100), 10);
        
        let level = 'Low';
        if (score >= 90) level = 'Critical';
        else if (score >= 75) level = 'High';
        else if (score >= 40) level = 'Medium';
        
        let reasonStr = '';
        if (reasons.length === 0) {
            reasonStr = `Threat signature match (${alert.category}) verified with ${(alert.confidence * 100).toFixed(1)}% confidence.`;
        } else {
            reasonStr = `Threat vector verified with ${(alert.confidence * 100).toFixed(1)}% confidence: ` + reasons.join(", ") + ".";
        }
        
        const actions = {
            'DoS': 'Block port and deploy rate-limiting rules on perimeter firewall.',
            'Probe': 'Blackhole source IP address and check target network port vulnerabilities.',
            'R2L': 'Force target user credential rotation and reset active session key tokens.',
            'U2R': 'Quarantine target machine (Isolate Network Node) and terminate child root processes.'
        };
        const action = actions[alert.category] || 'Inspect log details and enforce firewall restrictions.';
        
        return {
            score: score,
            level: level,
            reason: reasonStr,
            action: action
        };
    }

    function addThreatToPriorityQueue(alert) {
        if (alert.category === 'Normal') return;
        
        enrichAlertIndicators(alert);
        alert.priority = calculatePriority(alert);
        
        prioritizedQueue.push(alert);
        
        // Sort by priority score descending
        prioritizedQueue.sort((a, b) => b.priority.score - a.priority.score);
        
        // Keep top 5
        if (prioritizedQueue.length > 5) {
            prioritizedQueue = prioritizedQueue.slice(0, 5);
        }
        
        renderPriorityQueue();
    }

    function renderPriorityQueue() {
        const queueContainer = document.getElementById("priority-alert-queue");
        if (!queueContainer) return;
        
        if (prioritizedQueue.length === 0) {
            queueContainer.innerHTML = `
                <div class="queue-placeholder">
                    <p>Monitoring network... No critical threats prioritized.</p>
                </div>
            `;
            return;
        }
        
        queueContainer.innerHTML = "";
        prioritizedQueue.forEach(alert => {
            const item = document.createElement("div");
            const lvlClass = alert.priority.level.toLowerCase();
            item.className = `alert-queue-item ${lvlClass}`;
            
            item.innerHTML = `
                <div class="q-score-box">
                    <span class="q-score-lbl">Score</span>
                    <span class="q-score-val">${alert.priority.score}</span>
                </div>
                <div class="q-badge-box">
                    <span class="badge-threat ${alert.classKey}">${alert.category}</span>
                </div>
                <div class="q-reason-box">
                    <span class="q-reason-title">${alert.category} Vector Detected [${alert.timestamp}]</span>
                    <span class="q-reason-desc">${alert.priority.reason}</span>
                </div>
                <div class="q-action-box">
                    <strong>Mitigation Playbook</strong>
                    ${alert.priority.action}
                </div>
            `;
            queueContainer.appendChild(item);
        });
    }

    // Prepopulate alert options for mock stream
    const mockAttackPool = [
        { protocol: 'tcp', service: 'private', flag: 'S0', category: 'DoS', classKey: 'dos', severity: 'medium', mitigation: 'Block destination port via iptables rule' },
        { protocol: 'tcp', service: 'http', flag: 'SF', category: 'Normal', classKey: 'normal', severity: 'low', mitigation: 'Connection safe. Standard monitoring.' },
        { protocol: 'udp', service: 'domain_u', flag: 'SF', category: 'Normal', classKey: 'normal', severity: 'low', mitigation: 'Connection safe. Standard monitoring.' },
        { protocol: 'tcp', service: 'private', flag: 'SF', category: 'Probe', classKey: 'probe', severity: 'medium', mitigation: 'Activate rate-limiting on incoming scans' },
        { protocol: 'tcp', service: 'ftp_data', flag: 'SF', category: 'Normal', classKey: 'normal', severity: 'low', mitigation: 'Connection safe. Standard monitoring.' },
        { protocol: 'tcp', service: 'telnet', flag: 'SF', category: 'R2L', classKey: 'r2l', severity: 'high', mitigation: 'Block source IP; force session termination' },
        { protocol: 'tcp', service: 'smtp', flag: 'SF', category: 'Normal', classKey: 'normal', severity: 'low', mitigation: 'Connection safe. Standard monitoring.' },
        { protocol: 'tcp', service: 'ftp', flag: 'SF', category: 'R2L', classKey: 'r2l', severity: 'high', mitigation: 'Lock FTP credentials; check intrusion trail' },
        { protocol: 'tcp', service: 'private', flag: 'S0', category: 'DoS', classKey: 'dos', severity: 'medium', mitigation: 'Block destination port via iptables rule' },
        { protocol: 'icmp', service: 'eco_i', flag: 'SF', category: 'Probe', classKey: 'probe', severity: 'medium', mitigation: 'Drop ICMP echo request packets on gateway' },
        { protocol: 'tcp', service: 'root', flag: 'SF', category: 'U2R', classKey: 'u2r', severity: 'critical', mitigation: 'Quarantine target host; revoke admin tokens' },
    ];

    const alertsTableBody = document.querySelector("#alerts-table tbody");
    const alertsBadge = document.getElementById("alerts-badge");

    function renderAlertRow(alert, isLive = true) {
        const row = document.createElement("tr");
        
        // Severity styling
        let sevClass = "normal";
        let sevText = alert.severity;
        if (alert.priority && alert.priority.level) {
            sevText = alert.priority.level;
        }
        
        const sevLower = sevText.toLowerCase();
        if (sevLower === "critical") sevClass = "u2r";
        else if (sevLower === "high") sevClass = "r2l";
        else if (sevLower === "medium") sevClass = "probe";
        
        row.innerHTML = `
            <td>${alert.timestamp}</td>
            <td><code>${alert.protocol.toUpperCase()}</code></td>
            <td><code>${alert.service}</code></td>
            <td><code>${alert.flag}</code></td>
            <td><span class="badge-threat ${alert.classKey}">${alert.category}</span></td>
            <td><strong>${(alert.confidence * 100).toFixed(1)}%</strong></td>
            <td><span class="risk-label risk-${sevClass}">${sevText.toUpperCase()}</span></td>
            <td><button class="btn btn-secondary btn-xs btn-isolate" onclick="alert('Isolating host on firewall for transaction: ${alert.service}')">Isolate</button></td>
        `;

        if (isLive) {
            alertsTableBody.insertBefore(row, alertsTableBody.firstChild);
            // Keep table rows limited to 50
            if (alertsTableBody.children.length > 50) {
                alertsTableBody.removeChild(alertsTableBody.lastChild);
            }
        } else {
            alertsTableBody.appendChild(row);
        }
    }

    // Populate initial logs (12 rows)
    function buildInitialData() {
        // First load alerts from SQLite Database
        fetch("/api/db_alerts?limit=30")
            .then(res => res.json())
            .then(data => {
                if (data.status === "success" && data.alerts && data.alerts.length > 0) {
                    data.alerts.forEach(alert => {
                        const timestampStr = alert.timestamp.includes(" ") ? alert.timestamp.split(" ")[1] : alert.timestamp;
                        const alertItem = {
                            timestamp: timestampStr,
                            protocol: alert.protocol,
                            service: alert.service,
                            flag: alert.flag,
                            category: alert.prediction,
                            classKey: alert.prediction.toLowerCase(),
                            confidence: alert.confidence,
                            severity: alert.priority_level,
                            mitigation: alert.playbook_action,
                            priority: {
                                score: alert.priority_score,
                                level: alert.priority_level,
                                reason: alert.priority_reason,
                                action: alert.playbook_action
                            }
                        };
                        recentAlertsLog.push(alertItem);
                        totalPackets += 1;
                        threatDistribution[alertItem.classKey] = (threatDistribution[alertItem.classKey] || 0) + 1;
                        if (alertItem.category !== 'Normal') {
                            totalThreats += 1;
                            addThreatToPriorityQueue(alertItem);
                        }
                        renderAlertRow(alertItem, false);
                    });
                }
                
                // Then construct remaining mock connections
                const startTime = new Date();
                startTime.setMinutes(startTime.getMinutes() - 20);

                for (let i = 0; i < 15; i++) {
                    const timeOffset = new Date(startTime.getTime() + i * 80 * 1000);
                    const template = mockAttackPool[Math.floor(Math.random() * mockAttackPool.length)];
                    
                    const timestampStr = String(timeOffset.getHours()).padStart(2, '0') + ":" + 
                                         String(timeOffset.getMinutes()).padStart(2, '0') + ":" + 
                                         String(timeOffset.getSeconds()).padStart(2, '0');

                    const confidence = 0.85 + Math.random() * 0.15;
                    
                    const alertItem = {
                        timestamp: timestampStr,
                        protocol: template.protocol,
                        service: template.service,
                        flag: template.flag,
                        category: template.category,
                        classKey: template.classKey,
                        confidence: confidence,
                        severity: template.severity,
                        mitigation: template.mitigation
                    };

                    recentAlertsLog.push(alertItem);
                    
                    // Accumulate metrics
                    totalPackets += 1;
                    threatDistribution[template.classKey] += 1;
                    if (template.category !== 'Normal') {
                        totalThreats += 1;
                        addThreatToPriorityQueue(alertItem);
                    }
                    
                    renderAlertRow(alertItem, false);
                }
                
                // Initial dashboard numbers
                updateDashboardDOM();
                initializeTrendChart();
            })
            .catch(err => {
                console.error("Failed to load historical DB alerts:", err);
                
                // Fallback to only mock data
                const startTime = new Date();
                startTime.setMinutes(startTime.getMinutes() - 20);

                for (let i = 0; i < 15; i++) {
                    const timeOffset = new Date(startTime.getTime() + i * 80 * 1000);
                    const template = mockAttackPool[Math.floor(Math.random() * mockAttackPool.length)];
                    
                    const timestampStr = String(timeOffset.getHours()).padStart(2, '0') + ":" + 
                                         String(timeOffset.getMinutes()).padStart(2, '0') + ":" + 
                                         String(timeOffset.getSeconds()).padStart(2, '0');

                    const confidence = 0.85 + Math.random() * 0.15;
                    
                    const alertItem = {
                        timestamp: timestampStr,
                        protocol: template.protocol,
                        service: template.service,
                        flag: template.flag,
                        category: template.category,
                        classKey: template.classKey,
                        confidence: confidence,
                        severity: template.severity,
                        mitigation: template.mitigation
                    };

                    recentAlertsLog.push(alertItem);
                    
                    // Accumulate metrics
                    totalPackets += 1;
                    threatDistribution[template.classKey] += 1;
                    if (template.category !== 'Normal') {
                        totalThreats += 1;
                        addThreatToPriorityQueue(alertItem);
                    }
                    
                    renderAlertRow(alertItem, false);
                }
                updateDashboardDOM();
                initializeTrendChart();
            });
    }

    function updateDashboardDOM() {
        document.getElementById("stat-total-packets").textContent = totalPackets.toLocaleString();
        document.getElementById("stat-threats-count").textContent = totalThreats.toLocaleString();
        
        const threatPct = totalPackets > 0 ? (totalThreats / totalPackets) * 100 : 0;
        document.getElementById("stat-threats-pct").textContent = `${threatPct.toFixed(2)}% of traffic`;
        alertsBadge.textContent = totalThreats;
        
        // Calculate Risk Score
        let riskScore = 0;
        let riskLabel = "Normal";
        let riskClass = "risk-normal";
        
        if (threatPct > 0) {
            riskScore = Math.min(Math.round(threatPct * 1.8 + 15), 100);
        } else {
            riskScore = 5;
        }
        
        if (riskScore < 30) {
            riskLabel = "Normal";
            riskClass = "risk-normal";
        } else if (riskScore < 55) {
            riskLabel = "Warning";
            riskClass = "risk-medium";
        } else if (riskScore < 80) {
            riskLabel = "High";
            riskClass = "risk-high";
        } else {
            riskLabel = "Critical";
            riskClass = "risk-critical";
        }

        const riskEl = document.getElementById("stat-risk-score");
        riskEl.textContent = riskScore;
        
        const riskLabelEl = document.getElementById("risk-level-label");
        riskLabelEl.textContent = riskLabel;
        riskLabelEl.className = `risk-label ${riskClass}`;

        // Update pie chart datasets
        categoryChart.data.datasets[0].data = [
            threatDistribution.normal,
            threatDistribution.dos,
            threatDistribution.probe,
            threatDistribution.r2l,
            threatDistribution.u2r
        ];
        categoryChart.update();
    }

    function initializeTrendChart() {
        // Build mock time series
        const now = new Date();
        for (let i = 9; i >= 0; i--) {
            const time = new Date(now.getTime() - i * 60 * 1000);
            const labelStr = `${String(time.getHours()).padStart(2, '0')}:${String(time.getMinutes()).padStart(2, '0')}`;
            trendTimeLabels.push(labelStr);
            
            // Random distributions
            const normalCount = Math.floor(25 + Math.random() * 30);
            const threatCount = Math.floor(Math.random() * 8);
            trendNormalData.push(normalCount);
            trendThreatData.push(threatCount);
            
            totalPackets += (normalCount + threatCount);
            totalThreats += threatCount;
        }

        trendChart.data.labels = trendTimeLabels;
        trendChart.data.datasets[0].data = trendNormalData;
        trendChart.data.datasets[1].data = trendThreatData;
        trendChart.update();
    }

    // Live Simulator Tick (Every 5 seconds)
    function simulateTraffic() {
        const now = new Date();
        const labelStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
        
        // Add new packets
        const normalBatch = Math.floor(30 + Math.random() * 25);
        // Probability of threat occurrence
        const attackBatch = Math.random() > 0.45 ? Math.floor(Math.random() * 4) : 0;
        
        totalPackets += (normalBatch + attackBatch);
        totalThreats += attackBatch;
        
        threatDistribution.normal += normalBatch;
        
        // If threat packets were generated, append an alert row
        if (attackBatch > 0) {
            for (let k = 0; k < attackBatch; k++) {
                // Select only attack types (not index 1,2,4 which are Normal in pool)
                const attackPoolOnly = mockAttackPool.filter(x => x.category !== 'Normal');
                const template = attackPoolOnly[Math.floor(Math.random() * attackPoolOnly.length)];
                
                const confidence = 0.88 + Math.random() * 0.12;
                threatDistribution[template.classKey] += 1;

                const alertItem = {
                    timestamp: labelStr,
                    protocol: template.protocol,
                    service: template.service,
                    flag: template.flag,
                    category: template.category,
                    classKey: template.classKey,
                    confidence: confidence,
                    severity: template.severity,
                    mitigation: template.mitigation
                };
                
                renderAlertRow(alertItem, true);
                addThreatToPriorityQueue(alertItem);
            }
        }
        
        // Update line chart datasets (keep length of 10)
        const currentMinLabel = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
        if (trendTimeLabels[trendTimeLabels.length - 1] !== currentMinLabel) {
            trendTimeLabels.push(currentMinLabel);
            trendNormalData.push(normalBatch);
            trendThreatData.push(attackBatch);
            
            if (trendTimeLabels.length > 10) {
                trendTimeLabels.shift();
                trendNormalData.shift();
                trendThreatData.shift();
            }
            trendChart.data.labels = trendTimeLabels;
            trendChart.data.datasets[0].data = trendNormalData;
            trendChart.data.datasets[1].data = trendThreatData;
            trendChart.update();
        } else {
            // Accumulate within current minute
            trendNormalData[trendNormalData.length - 1] += normalBatch;
            trendThreatData[trendThreatData.length - 1] += attackBatch;
            trendChart.update();
        }
        
        updateDashboardDOM();
    }

    // Initialize stats and run background interval
    buildInitialData();
    setInterval(simulateTraffic, 5000);

    // Refresh Button Event
    document.getElementById("btn-refresh").addEventListener("click", () => {
        simulateTraffic();
        updateDashboardDOM();
    });

    // 6. Traffic Analyzer Page Presets Loading
    const presets = {
        normal: {
            duration: 0,
            protocol_type: "tcp",
            service: "ftp_data",
            flag: "SF",
            src_bytes: 491,
            dst_bytes: 0,
            count: 2,
            srv_count: 2,
            dst_host_count: 150,
            dst_host_srv_count: 25,
            num_failed_logins: 0,
            root_shell: 0,
            hot: 0,
            wrong_fragment: 0
        },
        dos: {
            duration: 0,
            protocol_type: "tcp",
            service: "private",
            flag: "S0",
            src_bytes: 0,
            dst_bytes: 0,
            count: 123,
            srv_count: 6,
            dst_host_count: 255,
            dst_host_srv_count: 26,
            num_failed_logins: 0,
            root_shell: 0,
            hot: 0,
            wrong_fragment: 3
        },
        probe: {
            duration: 0,
            protocol_type: "tcp",
            service: "private",
            flag: "SF",
            src_bytes: 0,
            dst_bytes: 0,
            count: 1,
            srv_count: 1,
            dst_host_count: 255,
            dst_host_srv_count: 1,
            num_failed_logins: 0,
            root_shell: 0,
            hot: 3,
            wrong_fragment: 0
        },
        r2l: {
            duration: 0,
            protocol_type: "tcp",
            service: "telnet",
            flag: "SF",
            src_bytes: 120,
            dst_bytes: 350,
            count: 1,
            srv_count: 1,
            dst_host_count: 2,
            dst_host_srv_count: 2,
            num_failed_logins: 85,
            root_shell: 0,
            hot: 4,
            wrong_fragment: 0
        }
    };

    function loadPresetValues(presetKey) {
        const val = presets[presetKey];
        if (!val) return;
        
        Object.keys(val).forEach(key => {
            const el = document.getElementById(`param-${key}`);
            if (el) {
                el.value = val[key];
            }
        });
    }

    document.getElementById("preset-normal").addEventListener("click", () => loadPresetValues("normal"));
    document.getElementById("preset-dos").addEventListener("click", () => loadPresetValues("dos"));
    document.getElementById("preset-probe").addEventListener("click", () => loadPresetValues("probe"));
    document.getElementById("preset-r2l").addEventListener("click", () => loadPresetValues("r2l"));

    // 7. Interactive Prediction Submission via API
    const formAnalyzer = document.getElementById("form-analyzer");
    const resultPlaceholder = document.getElementById("result-placeholder");
    const resultContent = document.getElementById("result-content");
    const threatBanner = document.getElementById("threat-banner");
    const threatClassText = document.getElementById("result-threat-class");
    const threatLevelText = document.getElementById("result-threat-level");
    const confidenceText = document.getElementById("result-confidence");
    const confidenceBar = document.getElementById("result-confidence-bar");
    const probBreakdownContainer = document.getElementById("prob-breakdown-rows");
    const mitigationContainer = document.getElementById("result-mitigation-list");
    const threatBannerIcon = document.getElementById("threat-banner-icon");

    const categoryMetaData = {
        "Normal": {
            severity: "NO THREAT DETECTED",
            classKey: "normal",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
            mitigation: [
                "Connection is marked safe. Standard threat log logged.",
                "Ensure standard endpoint protection remains active.",
                "No physical SOC actions are required for this transaction."
            ]
        },
        "DoS": {
            severity: "CRITICAL THREAT IN PROGRESS",
            classKey: "dos",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>`,
            mitigation: [
                "DoS signature matched. Block source address on perimeter firewall.",
                "Isolate target IP node from network segment immediately.",
                "Trigger rate-limiting policy for incoming traffic on matching ports."
            ]
        },
        "Probe": {
            severity: "WARNING: RECONNAISSANCE SCAN",
            classKey: "probe",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
            mitigation: [
                "Network scan detected. Apply block rules to the probing IP address.",
                "Audit target ports to verify they are not running vulnerable services.",
                "Verify stateful packet inspection logs for associated lateral movement."
            ]
        },
        "R2L": {
            severity: "HIGH THREAT: UNAUTHORIZED ACCESS ATTEMPT",
            classKey: "r2l",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
            mitigation: [
                "Unauthorized login vector. Force immediate session termination.",
                "Lock target host account credentials and require MFA reset.",
                "Review user activity audit trails for data exfiltration signs."
            ]
        },
        "U2R": {
            severity: "EMERGENCY: SYSTEM LEVEL COMPROMISE DETECTED",
            classKey: "u2r",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>`,
            mitigation: [
                "Quarantine target device from network immediately (Isolate Node).",
                "Terminate root access processes and perform memory state dump.",
                "Initiate immediate incident response forensics audit."
            ]
        }
    };

    formAnalyzer.addEventListener("submit", (e) => {
        e.preventDefault();
        
        // Build JSON payload by collecting all input elements in form
        const payload = {};
        
        // Numeric parameters
        const numericInputs = [
            "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment",
            "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
            "root_shell", "su_attempted", "num_root", "num_file_creations",
            "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
            "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
            "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
            "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
            "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
        ];
        
        numericInputs.forEach(key => {
            const el = document.getElementById(`param-${key}`);
            if (el) {
                payload[key] = parseFloat(el.value);
            }
        });
        
        // Categorical parameters
        const stringInputs = ["protocol_type", "service", "flag"];
        stringInputs.forEach(key => {
            const el = document.getElementById(`param-${key}`);
            if (el) {
                payload[key] = el.value;
            }
        });

        // Toggle submit button state
        const btnSubmit = document.getElementById("btn-submit-analyze");
        btnSubmit.disabled = true;
        btnSubmit.textContent = "Analyzing traffic...";

        fetch("/api/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        })
        .then(res => {
            if (!res.ok) {
                throw new Error(`Inference returned HTTP status ${res.status}`);
            }
            return res.json();
        })
        .then(result => {
            if (result.status === "success") {
                // Display Results
                resultPlaceholder.classList.add("hidden");
                resultContent.classList.remove("hidden");
                
                const meta = categoryMetaData[result.prediction];
                
                // Configure banner style
                threatBanner.className = `threat-output-banner ${meta.classKey}`;
                threatBannerIcon.innerHTML = meta.icon;
                threatClassText.textContent = result.prediction.toUpperCase();
                threatLevelText.textContent = meta.severity;
                
                // Confidence bar animation
                confidenceText.textContent = `${(result.confidence * 100).toFixed(2)}%`;
                confidenceBar.style.width = `${result.confidence * 100}%`;
                
                // Red/green progress color depending on threat status
                if (meta.classKey === 'normal') {
                    confidenceBar.style.backgroundColor = 'var(--color-normal)';
                } else {
                    confidenceBar.style.backgroundColor = 'var(--color-dos)';
                }

                // Update prioritization details box (Phase 6)
                const priorityBox = document.getElementById("result-prioritization-box");
                if (priorityBox) {
                    if (result.prediction === 'Normal') {
                        priorityBox.classList.add("hidden");
                    } else {
                        priorityBox.classList.remove("hidden");
                        priorityBox.className = `prioritization-details-box level-${result.priority_level.toLowerCase()}`;
                        document.getElementById("result-priority-score").textContent = result.priority_score;
                        document.getElementById("result-priority-level-badge").textContent = result.priority_level;
                        document.getElementById("result-priority-reason").textContent = result.priority_reason;
                        document.getElementById("result-playbook-action").textContent = result.playbook_action;
                    }
                }

                // Probability breakdown rows
                probBreakdownContainer.innerHTML = "";
                const sortedKeys = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'];
                sortedKeys.forEach(k => {
                    const probVal = result.probabilities[k];
                    const keyMeta = categoryMetaData[k];
                    
                    const row = document.createElement("div");
                    row.className = "prob-row";
                    row.innerHTML = `
                        <span class="prob-label">${k}</span>
                        <div class="prob-bar-track">
                            <div class="prob-bar-fill ${keyMeta.classKey}" style="width: ${probVal * 100}%"></div>
                        </div>
                        <span class="prob-value">${(probVal * 100).toFixed(1)}%</span>
                    `;
                    probBreakdownContainer.appendChild(row);
                });

                // Set mitigation list
                mitigationContainer.innerHTML = "";
                meta.mitigation.forEach(step => {
                    const li = document.createElement("li");
                    li.textContent = step;
                    mitigationContainer.appendChild(li);
                });
            } else {
                alert(`API Error: ${result.message}`);
            }
        })
        .catch(err => {
            alert(`Analysis failed: ${err.message}`);
        })
        .finally(() => {
            btnSubmit.disabled = false;
            btnSubmit.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px;">
                    <polygon points="22 2 15 22 11 13 2 9 22 2"/>
                </svg>
                Analyze Network Packet
            `;
        });
    });

    // 8. Alerts View Table Filters Client-side
    const filterSev = document.getElementById("filter-severity");
    const filterProt = document.getElementById("filter-protocol");
    const searchAlert = document.getElementById("search-alert");

    function applyFilters() {
        const sevVal = filterSev.value;
        const protVal = filterProt.value;
        const query = searchAlert.value.toLowerCase().trim();
        const rows = alertsTableBody.querySelectorAll("tr");

        rows.forEach(row => {
            let matchesSev = false;
            let matchesProt = false;
            let matchesQuery = false;

            // Severity check
            const sevBadge = row.querySelector(".risk-label");
            if (sevBadge) {
                const text = sevBadge.textContent.toLowerCase();
                if (sevVal === "all") matchesSev = true;
                else if (sevVal === "critical" && text === "critical") matchesSev = true;
                else if (sevVal === "high" && text === "high") matchesSev = true;
                else if (sevVal === "medium" && text === "medium") matchesSev = true;
                else if (sevVal === "low" && text === "low") matchesSev = true;
            }

            // Protocol check
            const cells = row.querySelectorAll("td");
            if (cells.length > 1) {
                const protocolText = cells[1].textContent.toLowerCase();
                if (protVal === "all" || protocolText.includes(protVal)) {
                    matchesProt = true;
                }
                
                // Search term check
                const serviceText = cells[2].textContent.toLowerCase();
                const flagText = cells[3].textContent.toLowerCase();
                const categoryText = cells[4].textContent.toLowerCase();
                
                if (query === "" || 
                    serviceText.includes(query) || 
                    flagText.includes(query) || 
                    categoryText.includes(query)) {
                    matchesQuery = true;
                }
            }

            if (matchesSev && matchesProt && matchesQuery) {
                row.style.display = "";
            } else {
                row.style.display = "none";
            }
        });
    }

    filterSev.addEventListener("change", applyFilters);
    filterProt.addEventListener("change", applyFilters);
    searchAlert.addEventListener("input", applyFilters);

    // 9. Model Performance page rendering & API integration
    let performanceDistributionChart = null;
    let featureImportanceChart = null;
    let metricsCache = null;

    function initPerformanceTab() {
        if (metricsCache) {
            renderPerformanceView(metricsCache);
            return;
        }

        fetch("/api/metrics")
            .then(res => {
                if (!res.ok) throw new Error(`HTTP status ${res.status}`);
                return res.json();
            })
            .then(data => {
                metricsCache = data;
                renderPerformanceView(data);
            })
            .catch(err => {
                console.error("Failed to load model performance metrics:", err);
                // Try fallback static metrics
                fetch("/static/metrics.json")
                    .then(res => res.json())
                    .then(data => {
                        metricsCache = data;
                        renderPerformanceView(data);
                    })
                    .catch(err2 => {
                        console.error("Fallback load failed:", err2);
                        alert("Could not load Model Performance metrics. Make sure model is trained and metrics.json exists.");
                    });
            });
    }

    function renderPerformanceView(data) {
        // 1. Core Metrics Cards
        document.getElementById("perf-accuracy").textContent = `${(data.accuracy * 100).toFixed(2)}%`;
        document.getElementById("perf-precision").textContent = `${(data.precision * 100).toFixed(2)}%`;
        document.getElementById("perf-recall").textContent = `${(data.recall * 100).toFixed(2)}%`;
        document.getElementById("perf-f1").textContent = `${(data.f1_score * 100).toFixed(2)}%`;

        // 2. Render Confusion Matrix Heatmap
        renderConfusionMatrixGrid(data.confusion_matrix);

        // 3. Class Distribution Grouped Bar Chart
        renderClassDistributionChart(data.class_distribution);

        // 4. Feature Importance Horizontal Bar Chart
        renderFeatureImportanceChart(data.top_features);

        // 5. Model Information Details Table
        renderModelInfoTable(data.model_info);
    }

    function renderConfusionMatrixGrid(matrix) {
        const gridContainer = document.getElementById("confusion-matrix-grid");
        if (!gridContainer) return;
        gridContainer.innerHTML = "";

        const classes = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'];
        
        // 1. Top-Left Corner Label Cell
        const cornerCell = document.createElement("div");
        cornerCell.className = "cm-corner-label";
        cornerCell.innerHTML = `
            <span class="act-lbl">Actual</span>
            <span class="pred-lbl">Predicted</span>
        `;
        gridContainer.appendChild(cornerCell);

        // 2. Column Headers (Predicted Classes)
        classes.forEach(c => {
            const cell = document.createElement("div");
            cell.className = "cm-cell cm-header-x";
            cell.innerHTML = `<strong>${c}</strong>`;
            gridContainer.appendChild(cell);
        });

        // 3. Rows (Actual Class header followed by 5 prediction cells)
        classes.forEach((actualClass, rIdx) => {
            // Row Header (Actual Class)
            const rowHeader = document.createElement("div");
            rowHeader.className = "cm-cell cm-header-y";
            rowHeader.innerHTML = `<strong>${actualClass}</strong>`;
            gridContainer.appendChild(rowHeader);

            const row = matrix[rIdx];
            const rowSum = row.reduce((a, b) => a + b, 0);

            // Row Cells
            row.forEach((value, cIdx) => {
                const isDiagonal = (rIdx === cIdx);
                const cellPct = rowSum > 0 ? (value / rowSum) * 100 : 0;
                
                // Classify color intensity
                let intensityClass = "cm-intensity-0";
                if (value > 0) {
                    if (cellPct < 5) intensityClass = "cm-intensity-1";
                    else if (cellPct < 25) intensityClass = "cm-intensity-2";
                    else if (cellPct < 50) intensityClass = "cm-intensity-3";
                    else if (cellPct < 85) intensityClass = "cm-intensity-4";
                    else intensityClass = "cm-intensity-5";
                }

                const cell = document.createElement("div");
                cell.className = `cm-cell ${intensityClass} ${isDiagonal ? 'cm-diagonal' : ''}`;
                cell.setAttribute("title", `Actual: ${actualClass}, Predicted: ${classes[cIdx]} \nValue: ${value.toLocaleString()} (${cellPct.toFixed(2)}%)`);
                
                cell.innerHTML = `
                    <span class="cm-value">${value.toLocaleString()}</span>
                    <span class="cm-percentage">${cellPct.toFixed(1)}%</span>
                `;
                gridContainer.appendChild(cell);
            });
        });
    }

    function renderClassDistributionChart(distribution) {
        const ctx = document.getElementById("performanceDistributionChart").getContext("2d");
        if (!ctx) return;

        if (performanceDistributionChart) {
            performanceDistributionChart.destroy();
        }

        const classes = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'];
        const trainData = classes.map(c => distribution.train[c] || 0);
        const valData = classes.map(c => distribution.val[c] || 0);
        const testData = classes.map(c => distribution.test[c] || 0);

        performanceDistributionChart = new Chart(ctx, {
            type: "bar",
            data: {
                labels: classes,
                datasets: [
                    {
                        label: "Train Split",
                        data: trainData,
                        backgroundColor: "rgba(56, 189, 248, 0.75)",
                        borderColor: "#38bdf8",
                        borderWidth: 1
                    },
                    {
                        label: "Val Split",
                        data: valData,
                        backgroundColor: "rgba(192, 132, 252, 0.75)",
                        borderColor: "#c084fc",
                        borderWidth: 1
                    },
                    {
                        label: "Test Split",
                        data: testData,
                        backgroundColor: "rgba(245, 158, 11, 0.75)",
                        borderColor: "#f59e0b",
                        borderWidth: 1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "#94a3b8", font: { family: "Outfit", size: 11 } }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return ` ${context.dataset.label}: ${context.raw.toLocaleString()} samples`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: "rgba(255, 255, 255, 0.03)" },
                        ticks: { color: "#94a3b8", font: { family: "Outfit" } }
                    },
                    y: {
                        type: "logarithmic",
                        grid: { color: "rgba(255, 255, 255, 0.03)" },
                        ticks: { 
                            color: "#94a3b8", 
                            font: { family: "Outfit" },
                            callback: function(value) {
                                if (value === 10 || value === 100 || value === 1000 || value === 10000 || value === 100000) {
                                    return value.toLocaleString();
                                }
                                return null;
                            }
                        }
                    }
                }
            }
        });
    }

    function renderFeatureImportanceChart(features) {
        const ctx = document.getElementById("featureImportanceChart").getContext("2d");
        if (!ctx) return;

        if (featureImportanceChart) {
            featureImportanceChart.destroy();
        }

        const sortedFeatures = [...features].reverse();
        const labels = sortedFeatures.map(f => f.name);
        const dataVals = sortedFeatures.map(f => f.importance);

        featureImportanceChart = new Chart(ctx, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "Relative Gini Importance",
                    data: dataVals,
                    backgroundColor: "rgba(56, 189, 248, 0.35)",
                    borderColor: "#38bdf8",
                    borderWidth: 1.5,
                    hoverBackgroundColor: "rgba(56, 189, 248, 0.65)",
                    hoverBorderColor: "#38bdf8",
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return ` Importance: ${(context.raw * 100).toFixed(3)}%`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: "rgba(255, 255, 255, 0.03)" },
                        ticks: { 
                            color: "#94a3b8", 
                            font: { family: "Outfit" },
                            callback: function(value) {
                                return `${(value * 100).toFixed(0)}%`;
                            }
                        }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: "#f8fafc", font: { family: "Outfit", weight: 500 } }
                    }
                }
            }
        });
    }

    function renderModelInfoTable(info) {
        const tableBody = document.querySelector("#model-info-table tbody");
        if (!tableBody) return;
        tableBody.innerHTML = "";

        const mapping = [
            { label: "Classifier Model", value: info.model_name },
            { label: "Number of Estimators (Trees)", value: info.n_estimators },
            { label: "Random Seed / State", value: info.random_state },
            { label: "Class Weighting", value: info.class_weight },
            { label: "Number of Input Features", value: info.n_features_in },
            { label: "Training Dataset size", value: `${info.training_samples.toLocaleString()} samples` },
            { label: "Validation Dataset size", value: `${info.validation_samples.toLocaleString()} samples` },
            { label: "Test Dataset size", value: `${info.test_samples.toLocaleString()} samples` },
            { label: "Model Generated At", value: info.timestamp }
        ];

        mapping.forEach(rowInfo => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="color: var(--color-text-secondary); width: 45%; padding: 10px 24px;"><strong>${rowInfo.label}</strong></td>
                <td style="font-family: monospace; font-weight: 600; padding: 10px 24px;">${rowInfo.value}</td>
            `;
            tableBody.appendChild(tr);
        });
    }

    // 10. PCAP Analyzer Tab logic
    function initPcapTab() {
        const dropzone = document.getElementById("pcap-dropzone");
        const fileInput = document.getElementById("pcap-file-input");
        if (!dropzone || !fileInput) return;

        // Prevent multiple listeners
        if (dropzone.dataset.listenerActive) return;
        dropzone.dataset.listenerActive = "true";

        dropzone.addEventListener("click", () => fileInput.click());

        fileInput.addEventListener("change", (e) => {
            if (fileInput.files.length > 0) {
                uploadAndProcessPcap(fileInput.files[0]);
            }
        });

        // Drag and drop event listeners
        ["dragenter", "dragover"].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add("dragover");
            }, false);
        });

        ["dragleave", "drop"].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove("dragover");
            }, false);
        });

        dropzone.addEventListener("drop", (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                uploadAndProcessPcap(files[0]);
            }
        }, false);
    }

    function uploadAndProcessPcap(file) {
        const ext = file.name.split('.').pop().toLowerCase();
        if (ext !== 'pcap' && ext !== 'pcapng') {
            alert("Please select a valid .pcap or .pcapng packet capture file.");
            return;
        }

        const progressContainer = document.getElementById("pcap-progress-container");
        const progressBar = document.getElementById("pcap-progress-bar");
        const progressPercent = document.getElementById("pcap-progress-percent");
        const statusLabel = document.getElementById("pcap-status-label");

        // Hide old stats and results
        document.getElementById("pcap-stats-section").classList.add("hidden");
        document.getElementById("pcap-results-section").classList.add("hidden");

        // Show progress loader
        progressContainer.classList.remove("hidden");
        progressBar.style.width = "0%";
        progressPercent.textContent = "0%";
        statusLabel.textContent = `Uploading ${file.name}...`;

        const formData = new FormData();
        formData.append("file", file);

        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/upload_pcap", true);

        // Upload progress tracking
        xhr.upload.addEventListener("progress", (e) => {
            if (e.lengthComputable) {
                const percentComplete = Math.round((e.loaded / e.total) * 100);
                const displayedPercent = Math.round(percentComplete * 0.75);
                progressBar.style.width = `${displayedPercent}%`;
                progressPercent.textContent = `${displayedPercent}%`;
                if (percentComplete === 100) {
                    statusLabel.textContent = "Analyzing packet streams... (This can take 5-15 seconds)";
                    progressBar.style.width = "85%";
                    progressPercent.textContent = "85%";
                }
            }
        });

        xhr.onload = function() {
            progressContainer.classList.add("hidden");
            if (xhr.status === 200) {
                const response = JSON.parse(xhr.responseText);
                if (response.status === "success") {
                    renderPcapResults(file.name, response.summary, response.results);
                } else {
                    alert(`PCAP Analysis Error: ${response.message}`);
                }
            } else {
                alert(`Upload failed with status: ${xhr.status}`);
            }
        };

        xhr.onerror = function() {
            progressContainer.classList.add("hidden");
            alert("A network error occurred while uploading PCAP file.");
        };

        xhr.send(formData);
    }

    function renderPcapResults(filename, summary, results) {
        // Show sections
        document.getElementById("pcap-stats-section").classList.remove("hidden");
        document.getElementById("pcap-results-section").classList.remove("hidden");

        // Update cards
        document.getElementById("pcap-stat-packets").textContent = summary.total_packets.toLocaleString();
        document.getElementById("pcap-stat-flows").textContent = summary.total_flows.toLocaleString();
        document.getElementById("pcap-stat-threats").textContent = summary.threat_count.toLocaleString();
        
        const threatPct = summary.total_flows > 0 ? (summary.threat_count / summary.total_flows) * 100 : 0;
        document.getElementById("pcap-stat-threat-pct").textContent = `${threatPct.toFixed(2)}% of connection flows`;
        document.getElementById("pcap-filename-label").textContent = filename;

        const riskEl = document.getElementById("pcap-stat-risk");
        const riskLabelEl = document.getElementById("pcap-risk-label");
        const iconWrapper = document.getElementById("pcap-risk-icon-wrapper");
        
        const riskScore = summary.max_risk;
        riskEl.textContent = riskScore;

        let riskLabel = "Normal";
        let riskClass = "risk-normal";
        let wrapperClass = "green";

        if (riskScore >= 90) {
            riskLabel = "Critical";
            riskClass = "risk-critical";
            wrapperClass = "red";
        } else if (riskScore >= 75) {
            riskLabel = "High";
            riskClass = "risk-high";
            wrapperClass = "yellow";
        } else if (riskScore >= 40) {
            riskLabel = "Warning";
            riskClass = "risk-medium";
            wrapperClass = "yellow";
        }

        riskLabelEl.textContent = riskLabel;
        riskLabelEl.className = `risk-label ${riskClass}`;
        iconWrapper.className = `stat-icon-wrapper ${wrapperClass}`;

        // Populate Table
        const tableBody = document.querySelector("#pcap-flows-table tbody");
        if (!tableBody) return;
        tableBody.innerHTML = "";

        if (results.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding: 30px; color: var(--color-text-secondary);">No connection flows extracted from PCAP.</td></tr>`;
            return;
        }

        const badgesMap = {
            "Normal": "normal",
            "DoS": "dos",
            "Probe": "probe",
            "R2L": "r2l",
            "U2R": "u2r"
        };

        const levelClassMap = {
            "Critical": "u2r",
            "High": "r2l",
            "Medium": "probe",
            "Low": "normal"
        };

        results.forEach(flow => {
            const tr = document.createElement("tr");
            if (flow.prediction !== "Normal") {
                tr.className = "threat-row";
            }

            const badgeClass = badgesMap[flow.prediction] || "normal";
            const lvlClass = levelClassMap[flow.priority_level] || "normal";

            tr.innerHTML = `
                <td style="font-family: monospace; font-size: 0.8rem;">${flow.timestamp}</td>
                <td>
                    <div style="display:flex; flex-direction:column; gap: 2px;">
                        <span><code>${flow.source_ip}:${flow.src_port}</code> ➔ <code>${flow.dest_ip}:${flow.dest_port}</code></span>
                        <span style="font-size:0.7rem; color:var(--color-text-secondary);">${flow.packet_count} packets</span>
                    </div>
                </td>
                <td><code style="text-transform: uppercase;">${flow.protocol}</code></td>
                <td>
                    <div style="display:flex; flex-direction:column; gap: 2px;">
                        <span>Service: <code>${flow.service}</code></span>
                        <span style="font-size:0.7rem; color:var(--color-text-secondary);">Flag: <code>${flow.flag}</code></span>
                    </div>
                </td>
                <td style="font-family: monospace; font-size: 0.8rem;">${flow.src_bytes.toLocaleString()} / ${flow.dst_bytes.toLocaleString()}</td>
                <td><span class="badge-threat ${badgeClass}">${flow.prediction}</span></td>
                <td style="font-family: monospace; font-weight: 700;">${(flow.confidence * 100).toFixed(1)}%</td>
                <td><span class="risk-label risk-${lvlClass}">${flow.priority_score} [${flow.priority_level}]</span></td>
                <td style="font-size: 0.8rem; line-height: 1.3;">
                    ${flow.prediction === 'Normal' ? 'Connection safe.' : `<strong>${flow.priority_level}</strong>: ${flow.playbook_action}`}
                </td>
            `;
            tableBody.appendChild(tr);
        });

        // Prepend PCAP threat alerts into the main alerts feed
        results.forEach(flow => {
            if (flow.prediction !== "Normal") {
                const timestampStr = flow.timestamp.includes(" ") ? flow.timestamp.split(" ")[1] : flow.timestamp;
                const alertItem = {
                    timestamp: timestampStr,
                    protocol: flow.protocol,
                    service: flow.service,
                    flag: flow.flag,
                    category: flow.prediction,
                    classKey: flow.prediction.toLowerCase(),
                    confidence: flow.confidence,
                    severity: flow.priority_level,
                    mitigation: flow.playbook_action,
                    priority: {
                        score: flow.priority_score,
                        level: flow.priority_level,
                        reason: flow.priority_reason,
                        action: flow.playbook_action
                    }
                };

                recentAlertsLog.unshift(alertItem);
                totalPackets += 1;
                threatDistribution[alertItem.classKey] = (threatDistribution[alertItem.classKey] || 0) + 1;
                totalThreats += 1;
                
                renderAlertRow(alertItem, true);
                addThreatToPriorityQueue(alertItem);
            }
        });
        
        updateDashboardDOM();
    }
});
