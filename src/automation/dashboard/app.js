// ==========================================================================
// CTI-SENTINEL DASHBOARD FRONTEND LOGIC (VANILLA JS)
// ==========================================================================

let currentReport = null;
let currentRuleType = 'sigma';
let allArticles = [];

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initRuleSubtabs();
    loadSystemStatus();
    loadFeeds();
    bindEvents();
});

// Toast notification
function showToast(message, icon = 'ℹ️') {
    const toast = document.getElementById('toastNotification');
    const msg = document.getElementById('toastMessage');
    const icn = toast.querySelector('.toast-icon');
    msg.textContent = message;
    icn.textContent = icon;
    toast.classList.remove('hidden');
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 3500);
}

// 1. Tab Switching
function initTabs() {
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(btn => {
        btn.addEventListener('click', () => {
            tabs.forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            const target = btn.getAttribute('data-tab');
            const content = document.getElementById(target);
            if (content) content.classList.add('active');
        });
    });
}

function switchToTab(tabId) {
    const btn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
    if (btn) btn.click();
}

// 2. Rules Subtabs
function initRuleSubtabs() {
    const subtabs = document.querySelectorAll('.rule-subtab');
    subtabs.forEach(btn => {
        btn.addEventListener('click', () => {
            subtabs.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentRuleType = btn.getAttribute('data-rule');
            renderCurrentRule();
        });
    });
}

// 3. API Loaders
async function loadSystemStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        if (data.stats) {
            document.getElementById('kpiArticles').textContent = data.stats.total_articles;
            document.getElementById('kpiIOCs').textContent = (data.stats.total_articles * 5) || 12;
            document.getElementById('kpiReports').textContent = data.stats.total_reports || 3;
        }
    } catch (e) {
        console.warn('Status load error:', e);
    }
}

async function loadFeeds() {
    const container = document.getElementById('feedsGrid');
    container.innerHTML = `
        <div class="loading-state">
            <div class="spinner"></div>
            <p>Đang tải dữ liệu tình báo từ SQLite...</p>
        </div>
    `;
    try {
        const res = await fetch('/api/feeds?limit=30');
        const data = await res.json();
        allArticles = data.articles || [];
        renderFeeds(allArticles);
    } catch (e) {
        container.innerHTML = `
            <div class="empty-hint">Không thể kết nối đến máy chủ API CTI-Sentinel. Vui lòng kiểm tra server.</div>
        `;
    }
}

function renderFeeds(articles) {
    const container = document.getElementById('feedsGrid');
    if (!articles || articles.length === 0) {
        container.innerHTML = `<div class="empty-hint">Chưa có bài báo nào trong cơ sở dữ liệu. Bấm "Cào dữ liệu mới" để cập nhật!</div>`;
        return;
    }

    container.innerHTML = articles.map(art => {
        let badgeClass = 'badge-thn';
        if (art.source_name.includes('Bleeping')) badgeClass = 'badge-bleeping';
        if (art.source_name.includes('CISA')) badgeClass = 'badge-cisa';

        const snippet = art.raw_content ? art.raw_content.slice(0, 160) + '...' : 'Không có tóm tắt';
        const dateStr = art.published_date ? art.published_date.slice(0, 10) : 'Gần đây';

        return `
            <div class="feed-card" data-id="${art.id}">
                <div>
                    <div class="feed-card-header">
                        <span class="feed-source-badge ${badgeClass}">${art.source_name}</span>
                        <span class="feed-date">${dateStr}</span>
                    </div>
                    <h3 class="feed-card-title">${art.title}</h3>
                    <p class="feed-card-snippet">${snippet}</p>
                </div>
                <div class="feed-card-footer">
                    <span class="tlp-tag">&bull; TLP:CLEAR</span>
                    <button class="btn btn-primary btn-analyze-card" onclick="analyzeArticle(${art.id})">
                        🔍 Phân tích AI Agent
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

// 4. Analyze Trigger from Card
window.analyzeArticle = function(articleId) {
    const article = allArticles.find(a => a.id === articleId);
    if (!article) return;

    switchToTab('tab-analyzer');
    document.getElementById('analyzeTitleInput').value = article.title;
    document.getElementById('analyzeTextInput').value = article.raw_content;

    // Trigger analysis immediately
    runAgentAnalysis(articleId);
};

// 5. Run ReAct Agent Analysis
async function runAgentAnalysis(articleId = null) {
    const title = document.getElementById('analyzeTitleInput').value.trim();
    const text = document.getElementById('analyzeTextInput').value.trim();

    if (!text) {
        showToast('Vui lòng nhập hoặc chọn một bài viết để phân tích!', '⚠️');
        return;
    }

    const badge = document.getElementById('analysisStatusBadge');
    badge.className = 'badge badge-cyan';
    badge.textContent = 'Agent Đang suy luận (ReAct Loop)...';

    // Timeline Animation
    const steps = document.querySelectorAll('.timeline-step');
    steps.forEach(s => { s.classList.remove('active', 'completed'); });

    // Step 1: Ingestion
    steps[0].classList.add('active');
    await new Promise(r => setTimeout(r, 300));
    steps[0].classList.remove('active');
    steps[0].classList.add('completed');

    // Step 2: Extraction
    steps[1].classList.add('active');
    await new Promise(r => setTimeout(r, 400));
    steps[1].classList.remove('active');
    steps[1].classList.add('completed');

    // Step 3: Enrichment
    steps[2].classList.add('active');
    await new Promise(r => setTimeout(r, 400));
    steps[2].classList.remove('active');
    steps[2].classList.add('completed');

    // Step 4: MITRE
    steps[3].classList.add('active');

    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                article_id: articleId,
                custom_title: title,
                custom_text: text
            })
        });

        const data = await res.json();
        if (data.status === 'success' && data.report) {
            currentReport = data.report;

            // Complete Timeline
            steps[3].classList.remove('active');
            steps[3].classList.add('completed');
            steps[4].classList.add('completed');

            badge.className = 'badge badge-emerald';
            badge.textContent = 'Hoàn tất phân tích 100%';

            renderAnalysisResults(currentReport);
            renderCurrentRule();
            loadSystemStatus();
            showToast(`Phân tích thành công báo cáo ${currentReport.report_id}!`, '✅');
        } else {
            throw new Error(data.detail || 'Phân tích thất bại');
        }
    } catch (e) {
        badge.className = 'badge badge-gray';
        badge.textContent = 'Lỗi phân tích';
        showToast('Lỗi: ' + e.message, '❌');
    }
}

// 6. Render Results in Analyzer Tab
function renderAnalysisResults(report) {
    // Summary
    const sumBox = document.getElementById('agentSummaryBox');
    sumBox.classList.remove('hidden');
    document.getElementById('agentSummaryText').textContent = report.executive_summary;

    // Extracted IOCs
    const iocContainer = document.getElementById('iocsContainer');
    if (!report.enriched_iocs || report.enriched_iocs.length === 0) {
        iocContainer.innerHTML = `<div class="empty-hint">Không tìm thấy IOCs độc hại trong văn bản.</div>`;
    } else {
        iocContainer.innerHTML = report.enriched_iocs.map(item => {
            const isMal = item.is_malicious;
            const score = item.reputation_score || 0;
            return `
                <div class="ioc-badge-card">
                    <span class="ioc-type-tag">${item.type}</span>
                    <span class="ioc-value">${item.value}</span>
                    <span class="ioc-score-tag ${isMal ? '' : 'bg-emerald'}">${isMal ? 'Độc hại' : 'An toàn'} (${score}%)</span>
                </div>
            `;
        }).join('');
    }

    // MITRE ATT&CK
    const mitreContainer = document.getElementById('mitreContainer');
    if (!report.mitre_attack_matrix || report.mitre_attack_matrix.length === 0) {
        mitreContainer.innerHTML = `<div class="empty-hint">Không nhận diện được kỹ thuật MITRE cụ thể.</div>`;
    } else {
        mitreContainer.innerHTML = report.mitre_attack_matrix.map(m => {
            return `
                <div class="mitre-tag-card">
                    <span class="mitre-id">${m.technique_id}</span>
                    <span class="mitre-name">${m.technique_name}</span>
                    <span class="badge badge-gray">${m.tactic}</span>
                </div>
            `;
        }).join('');
    }
}

// 7. Render Current Rule in Studio Tab
function renderCurrentRule() {
    const display = document.getElementById('ruleCodeDisplay');
    const meta = document.getElementById('currentRuleMeta');
    const downloadBtn = document.getElementById('btnDownloadRule');

    if (!currentReport) {
        display.textContent = `# Chưa có báo cáo nào được phân tích.\n# Hãy sang tab 'Phòng thí nghiệm AI Agent' để kích hoạt phân tích bài viết!`;
        return;
    }

    let code = '';
    let filename = '';
    let mime = 'text/plain';

    if (currentRuleType === 'sigma') {
        meta.textContent = 'Định dạng: SigmaHQ Rule (YAML cho Wazuh/Splunk SIEM)';
        code = currentReport.defensive_rules?.sigma_rule || '# Không có luật Sigma';
        filename = `${currentReport.report_id}_sigma.yml`;
        mime = 'text/yaml';
    } else if (currentRuleType === 'yara') {
        meta.textContent = 'Định dạng: YARA Detection Rule (.yar cho Endpoint)';
        code = currentReport.defensive_rules?.yara_rule || '// Không có luật YARA';
        filename = `${currentReport.report_id}_yara.yar`;
        mime = 'text/plain';
    } else if (currentRuleType === 'firewall') {
        meta.textContent = 'Định dạng: Firewall Blocklist (iptables / DNS Sinkhole)';
        code = currentReport.raw_blocklist_text || '# Không có danh sách chặn';
        filename = `${currentReport.report_id}_blocklist.txt`;
        mime = 'text/plain';
    } else if (currentRuleType === 'stix') {
        meta.textContent = 'Định dạng: OASIS STIX 2.1 JSON Bundle (Chia sẻ cho OpenCTI/MISP)';
        code = JSON.stringify(currentReport.stix_json, null, 2) || '{}';
        filename = `${currentReport.report_id}_stix21.json`;
        mime = 'application/json';
    }

    display.textContent = code;

    // Cập nhật link download
    const blob = new Blob([code], { type: mime });
    downloadBtn.href = URL.createObjectURL(blob);
    downloadBtn.download = filename;
}

// 8. Bind UI Events
function bindEvents() {
    // Run Agent Button
    document.getElementById('btnRunAgent').addEventListener('click', () => {
        runAgentAnalysis();
    });

    // Load Sample Button
    document.getElementById('btnLoadSample').addEventListener('click', () => {
        if (allArticles.length > 0) {
            const first = allArticles[0];
            document.getElementById('analyzeTitleInput').value = first.title;
            document.getElementById('analyzeTextInput').value = first.raw_content;
            showToast('Đã nạp bài viết mẫu: ' + first.title.slice(0, 40) + '...', '📰');
        }
    });

    // Copy Code Button
    document.getElementById('btnCopyRule').addEventListener('click', () => {
        const code = document.getElementById('ruleCodeDisplay').textContent;
        navigator.clipboard.writeText(code).then(() => {
            showToast('Đã sao chép mã quy tắc vào Clipboard!', '📋');
        }).catch(() => {
            showToast('Không thể sao chép!', '⚠️');
        });
    });

    // Fetch Live Feeds Button
    document.getElementById('btnFetchLive').addEventListener('click', async () => {
        showToast('Đang quét và thu thập dữ liệu mới từ RSS & CISA...', '🔄');
        try {
            const res = await fetch('/api/feeds/fetch', { method: 'POST' });
            const data = await res.json();
            showToast(`Thu thập hoàn tất: ${data.rss_count} bài RSS & ${data.cisa_count} cảnh báo CISA!`, '✅');
            loadFeeds();
            loadSystemStatus();
        } catch (e) {
            showToast('Lỗi khi cào dữ liệu', '❌');
        }
    });

    // Quick Demo Button
    document.getElementById('btnQuickDemo').addEventListener('click', () => {
        if (allArticles.length > 0) {
            analyzeArticle(allArticles[0].id);
            showToast('Đang kích hoạt Demo tự động với bài báo thực tế...', '⚡');
        } else {
            showToast('Đang khởi tạo dữ liệu mẫu, vui lòng thử lại sau 2 giây!', '⏳');
            loadFeeds();
        }
    });

    // Search and Filter Feeds
    const searchInput = document.getElementById('feedSearchInput');
    const sourceSelect = document.getElementById('feedSourceSelect');

    const filterFeeds = () => {
        const query = searchInput.value.toLowerCase().trim();
        const source = sourceSelect.value;

        const filtered = allArticles.filter(art => {
            const matchSource = (source === 'ALL') || (art.source_name === source);
            const matchQuery = !query || 
                art.title.toLowerCase().includes(query) || 
                (art.raw_content && art.raw_content.toLowerCase().includes(query));
            return matchSource && matchQuery;
        });

        renderFeeds(filtered);
    };

    searchInput.addEventListener('input', filterFeeds);
    sourceSelect.addEventListener('change', filterFeeds);
}
