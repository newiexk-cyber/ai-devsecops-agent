/**
 * ==============================================================================
 * CTI-SENTINEL FRONTEND ORCHESTRATOR (LÂM)
 * - Phân tích bản tin CTI với Hybrid Local LLM (Ollama) & Regex Fallback
 * - Sinh Dynamic Agent Skill & Kiểm chứng AST/Sandbox
 * - Gán nhãn tay 50 bài báo thật & Đo Precision/Recall/F1 thực nghiệm
 * ==============================================================================
 */

const state = {
    feeds: [],
    selectedArticle: null,
    currentReport: null,
    currentSkill: null,
    currentSchemaTab: 'python',
    corpus: [],
    selectedCorpusArticle: null,
    selectedRegexHints: null,
};

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function sanitizeUrl(url) {
    if (!url || typeof url !== 'string') return '#';
    const trimmed = url.trim();
    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    return '#';
}

function showToast(msg) {
    const toast = document.getElementById('appToast');
    const txt = document.getElementById('toastText');
    if (!toast || !txt) return;
    txt.textContent = msg;
    toast.classList.remove('hidden');
    clearTimeout(window.__toastTimer);
    window.__toastTimer = setTimeout(() => {
        toast.classList.add('hidden');
    }, 3500);
}

function switchTab(tabId) {
    document.querySelectorAll('.nav-tab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabId);
    });
    document.querySelectorAll('.tab-view').forEach(view => {
        view.classList.toggle('active', view.id === tabId);
    });
}

async function initApp() {
    bindEvents();
    await Promise.all([
        refreshSystemStatus(),
        loadFeeds(),
        loadCorpusList(),
        loadLatestBenchmark(),
    ]);
}

function bindEvents() {
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    const btnFetchLive = document.getElementById('btnFetchLive');
    if (btnFetchLive) btnFetchLive.addEventListener('click', triggerLiveFetch);

    const btnCve = document.getElementById('btnSubmitOnDemandCve');
    if (btnCve) btnCve.addEventListener('click', handleFetchCve);

    const searchInput = document.getElementById('feedSearchInput');
    if (searchInput) searchInput.addEventListener('input', () => renderFeedList());

    const btnAnalyze = document.getElementById('btnRunAnalysis');
    if (btnAnalyze) btnAnalyze.addEventListener('click', runAnalysis);

    const btnGoSkill = document.getElementById('btnGoToSkillStudio');
    if (btnGoSkill) btnGoSkill.addEventListener('click', () => switchTab('tab-skill-studio'));

    // Event delegation for feed cards
    const feedList = document.getElementById('feedCardList');
    if (feedList) {
        feedList.addEventListener('click', e => {
            const card = e.target.closest('.threat-card');
            if (!card) return;
            const aid = Number(card.dataset.id);
            const found = state.feeds.find(x => x.id === aid);
            if (found) selectFeedArticle(found);
        });
    }

    // Skill Studio schema tabs
    const schemaTabs = document.getElementById('skillSchemaTabs');
    if (schemaTabs) {
        schemaTabs.addEventListener('click', e => {
            const btn = e.target.closest('.model-tab-btn');
            if (!btn) return;
            state.currentSchemaTab = btn.dataset.schema;
            schemaTabs.querySelectorAll('.model-tab-btn').forEach(b => {
                b.classList.toggle('active', b === btn);
            });
            renderSkillCode();
        });
    }

    const btnVerifySkill = document.getElementById('btnVerifySkillSandbox');
    if (btnVerifySkill) btnVerifySkill.addEventListener('click', verifyCurrentSkillSandbox);

    const btnDlSkill = document.getElementById('btnDownloadPythonSkill');
    if (btnDlSkill) {
        btnDlSkill.addEventListener('click', () => {
            if (!state.currentReport) return;
            window.location.href = `/api/download/${encodeURIComponent(state.currentReport.report_id)}/skill`;
        });
    }

    const btnDlStix = document.getElementById('btnDownloadStixBundle');
    if (btnDlStix) {
        btnDlStix.addEventListener('click', () => {
            if (!state.currentReport) return;
            window.location.href = `/api/download/${encodeURIComponent(state.currentReport.report_id)}/stix`;
        });
    }

    // Corpus & Benchmark events
    const corpusList = document.getElementById('corpusArticleList');
    if (corpusList) {
        corpusList.addEventListener('click', e => {
            const card = e.target.closest('.threat-card');
            if (!card) return;
            loadCorpusArticleDetail(card.dataset.articleId);
        });
    }

    const btnRefreshCorpus = document.getElementById('btnRefreshCorpus');
    if (btnRefreshCorpus) btnRefreshCorpus.addEventListener('click', collectCorpus50);

    const btnPrefill = document.getElementById('btnPrefillRegexHints');
    if (btnPrefill) btnPrefill.addEventListener('click', prefillRegexHints);

    const btnSaveAnn = document.getElementById('btnSaveAnnotation');
    if (btnSaveAnn) btnSaveAnn.addEventListener('click', saveAnnotation);

    const btnRunBench = document.getElementById('btnRunBenchmark');
    if (btnRunBench) btnRunBench.addEventListener('click', runBenchmark);
}

async function refreshSystemStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        const stats = data.stats || {};
        const ollama = data.ollama_health || {};
        const corpus = data.corpus_summary || {};

        document.getElementById('kpiTotalArticles').textContent = stats.total_articles || 0;
        document.getElementById('kpiTotalReports').textContent = stats.total_reports || 0;
        document.getElementById('kpiVerifiedCorpus').textContent = `${corpus.human_verified_count || 0} / ${corpus.total_articles || 50}`;
        document.getElementById('navVerifiedBadge').textContent = `${corpus.human_verified_count || 0}/${corpus.total_articles || 50} duyệt`;

        const dot = document.getElementById('ollamaStatusDot');
        const lbl = document.getElementById('ollamaStatusLabel');
        const modelEl = document.getElementById('kpiLlmModel');
        const subEl = document.getElementById('kpiLlmSub');

        if (ollama.online && ollama.model_available) {
            dot.className = 'status-dot online';
            lbl.textContent = `LOCAL LLM ONLINE (${ollama.configured_model})`;
            modelEl.textContent = ollama.configured_model;
            modelEl.className = 'metric-value text-emerald';
            subEl.textContent = `Ollama Sẵn Sàng (${ollama.base_url})`;
        } else if (ollama.online) {
            dot.className = 'status-dot online';
            lbl.textContent = `OLLAMA ONLINE (Chưa kéo ${ollama.configured_model})`;
            modelEl.className = 'metric-value text-amber';
            subEl.textContent = `Models: ${(ollama.available_models || []).join(', ') || 'trống'}`;
        } else {
            dot.className = 'status-dot offline';
            lbl.textContent = 'OLLAMA OFFLINE (Dùng Regex Fallback)';
            modelEl.className = 'metric-value text-crimson';
            subEl.textContent = 'Bật Ollama hoặc chọn Regex Baseline';
        }
    } catch (err) {
        console.error('Status error:', err);
    }
}

async function loadFeeds() {
    try {
        const res = await fetch('/api/feeds?limit=80');
        const data = await res.json();
        state.feeds = data.articles || [];
        document.getElementById('navArticleCount').textContent = state.feeds.length;
        renderFeedList();
    } catch (err) {
        showToast('Không thể tải danh sách bản tin CTI.');
    }
}

function renderFeedList() {
    const container = document.getElementById('feedCardList');
    const q = (document.getElementById('feedSearchInput')?.value || '').trim().toLowerCase();
    const filtered = state.feeds.filter(item => {
        if (!q) return true;
        return (item.title || '').toLowerCase().includes(q)
            || (item.raw_content || '').toLowerCase().includes(q)
            || (item.source_name || '').toLowerCase().includes(q);
    });

    document.getElementById('lblFeedCounter').textContent = `${filtered.length} tin`;
    if (!filtered.length) {
        container.innerHTML = '<div class="details-empty"><p>Không có bản tin nào khớp bộ lọc.</p></div>';
        return;
    }

    container.innerHTML = filtered.map(item => {
        const isSelected = state.selectedArticle && state.selectedArticle.id === item.id;
        const pub = item.published_date ? String(item.published_date).slice(0, 16) : 'Chưa rõ ngày';
        const analyzedBadge = item.is_analyzed
            ? '<span class="badge badge-verified">ĐÃ PHÂN TÍCH</span>'
            : '<span class="badge badge-date">MỚI</span>';
        return `
            <div class="threat-card ${isSelected ? 'active' : ''}" data-id="${escapeHtml(item.id)}">
                <div class="threat-card-top">
                    <span class="badge badge-vendor">${escapeHtml(item.source_name)}</span>
                    ${analyzedBadge}
                </div>
                <div class="threat-card-title">${escapeHtml(item.title)}</div>
                <div class="threat-card-meta">
                    <span>${escapeHtml(pub)}</span>
                    <span>${escapeHtml((item.raw_content || '').length)} ký tự</span>
                </div>
            </div>
        `;
    }).join('');
}

function selectFeedArticle(article) {
    state.selectedArticle = article;
    document.getElementById('analyzeTitleInput').value = article.title || '';
    document.getElementById('analyzeTextInput').value = article.raw_content || '';
    renderFeedList();
}

async function triggerLiveFetch() {
    const btn = document.getElementById('btnFetchLive');
    btn.disabled = true;
    btn.textContent = 'Đang cào RSS & CISA...';
    try {
        const res = await fetch('/api/feeds/fetch?limit=25', { method: 'POST' });
        const data = await res.json();
        showToast(data.message || 'Đã cập nhật tin CTI mới.');
        await Promise.all([loadFeeds(), refreshSystemStatus()]);
    } catch (err) {
        showToast('Lỗi khi cào bản tin mới.');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Cào Tin CTI Mới';
    }
}

async function handleFetchCve() {
    const input = document.getElementById('inputOnDemandCve');
    const cve = (input.value || '').trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(cve)) {
        showToast('Mã CVE phải đúng chuẩn (vd: CVE-2024-3400)');
        return;
    }
    try {
        const res = await fetch('/api/feeds/fetch-cve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cve_id: cve }),
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.detail || 'Không tìm thấy CVE');
            return;
        }
        showToast(data.message);
        await loadFeeds();
    } catch (err) {
        showToast('Lỗi truy vấn CVE từ CISA/NVD.');
    }
}

async function runAnalysis() {
    const title = document.getElementById('analyzeTitleInput').value.trim();
    const text = document.getElementById('analyzeTextInput').value.trim();
    const mode = document.getElementById('selectAnalyzeMode').value;

    if (!text) {
        showToast('Vui lòng chọn bài viết hoặc dán nội dung bản tin CTI.');
        return;
    }

    const btn = document.getElementById('btnRunAnalysis');
    btn.disabled = true;
    btn.textContent = mode === 'hybrid' ? 'Local Agent đang đọc...' : 'Đang trích xuất...';

    const payload = {
        article_id: state.selectedArticle && state.selectedArticle.raw_content === text ? state.selectedArticle.id : null,
        custom_title: title || 'Báo cáo CTI Tùy chỉnh',
        custom_text: text,
        mode,
    };

    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.detail || 'Phân tích thất bại');
            return;
        }

        state.currentReport = data.report;
        state.currentSkill = data.agent_skill;
        renderAnalysisReport(data.report);
        renderSkillStudio(data.agent_skill);
        showToast(`Phân tích xong (${data.report.analysis_mode})!`);
        await Promise.all([loadFeeds(), refreshSystemStatus()]);
    } catch (err) {
        showToast('Lỗi kết nối tới API phân tích.');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Phân Tích & Sinh Skill';
    }
}

function renderAnalysisReport(report) {
    document.getElementById('analysisEmptyState').classList.add('hidden');
    document.getElementById('analysisResultPanel').classList.remove('hidden');

    document.getElementById('resModeBadge').textContent = (report.analysis_mode || 'unknown').toUpperCase();
    document.getElementById('resReportId').textContent = report.report_id || '--';
    const actors = (report.threat_actors || []).concat(report.malware_families || []);
    document.getElementById('resActorsLabel').textContent = `Thực thể: ${actors.length ? actors.join(', ') : 'Chưa định danh'}`;
    document.getElementById('resTitle').textContent = report.title || '--';
    document.getElementById('resSummary').textContent = report.executive_summary || '--';

    const iocBody = document.getElementById('resIocTableBody');
    const iocs = report.enriched_iocs || [];
    if (!iocs.length) {
        iocBody.innerHTML = '<tr><td colspan="4">Không tìm thấy IOC hợp lệ trong bài viết này.</td></tr>';
    } else {
        iocBody.innerHTML = iocs.map(item => {
            const verdictCls = item.is_malicious ? 'text-crimson' : (item.is_verified ? 'text-emerald' : 'text-amber');
            const label = item.is_malicious ? `ĐỘC HẠI (${item.reputation_score})` : (item.is_verified ? 'SẠCH / XÁC MINH' : 'CHƯA XÁC MINH');
            return `
                <tr>
                    <td>${escapeHtml(item.type)}</td>
                    <td>${escapeHtml(item.value)}</td>
                    <td>${escapeHtml(item.enrichment_source)}</td>
                    <td class="${verdictCls}">${escapeHtml(label)}</td>
                </tr>
            `;
        }).join('');
    }

    const xai = report.xai_report || {};
    const rList = document.getElementById('resReasoningList');
    rList.innerHTML = (xai.reasoning_chain || []).map(step => `<div class="reasoning-step">${escapeHtml(step)}</div>`).join('')
        || '<div class="reasoning-step">Không có bước lập luận.</div>';

    const qList = document.getElementById('resEvidenceQuotes');
    qList.innerHTML = (xai.evidence_quotes || []).map(q => `<div class="reasoning-step">"${escapeHtml(q)}"</div>`).join('')
        || '<div class="reasoning-step">Không có trích dẫn nguyên văn.</div>';

    const droppedBox = document.getElementById('resDroppedIocs');
    const dropped = report.dropped_iocs || [];
    droppedBox.innerHTML = dropped.length
        ? dropped.map(d => `<span class="evidence-chip">${escapeHtml(d.type)}: ${escapeHtml(d.value)} — ${escapeHtml(d.reason)}</span>`).join('')
        : '<span class="evidence-chip">Không có ứng viên bị loại.</span>';

    const mitreBox = document.getElementById('resMitreTags');
    const mitre = report.mitre_attack_matrix || [];
    mitreBox.innerHTML = mitre.length
        ? mitre.map(m => `<span class="evidence-chip">${escapeHtml(m.technique_id)} (${escapeHtml(m.technique_name)})</span>`).join('')
        : '<span class="evidence-chip">Không ánh xạ được kỹ thuật MITRE ATT&CK rõ ràng.</span>';
}

function renderSkillStudio(skill) {
    const empty = document.getElementById('skillEmptyState');
    const panel = document.getElementById('skillActivePanel');
    const navBadge = document.getElementById('navSkillBadge');

    if (!skill || !skill.skill_name) {
        empty.classList.remove('hidden');
        panel.classList.add('hidden');
        return;
    }

    empty.classList.add('hidden');
    panel.classList.remove('hidden');

    navBadge.textContent = skill.execution_status || 'READY';
    document.getElementById('skillNameHeader').textContent = `SKILL: ${skill.skill_name}`;
    document.getElementById('skillExecStatusBadge').textContent = skill.execution_status || 'DRY_RUN';
    document.getElementById('skillAstStatusBadge').textContent = `AST Safe: ${skill.ast_safe} | Syntax Valid: ${skill.code_compiled_successfully}`;
    document.getElementById('skillSummaryDesc').textContent = skill.description || '';
    document.getElementById('skillSystemPrompt').textContent = skill.system_prompt || '';

    renderSkillCode();
    renderSandboxVerification(skill.verification);
}

function renderSkillCode() {
    if (!state.currentSkill) return;
    const schemas = state.currentSkill.model_schemas || {};
    const code = schemas[state.currentSchemaTab] || state.currentSkill.execution_code || '// Không có mã skill';
    document.getElementById('skillCodeDisplay').textContent = code;
}

function renderSandboxVerification(ver) {
    const box = document.getElementById('skillSandboxReportBox');
    if (!ver) {
        box.innerHTML = '<div class="reasoning-step">Chưa có dữ liệu kiểm chứng sandbox.</div>';
        return;
    }
    const lines = [
        `AST Safety Check: ${ver.ast_safe ? 'AN TOÀN (Không hàm nguy hiểm)' : 'BỊ CHẶN: ' + (ver.violations || []).join(', ')}`,
        `Kiểm tra cú pháp (compile): ${ver.syntax_valid ? 'HỢP LỆ (100%)' : 'LỖI: ' + (ver.error || '')}`,
        `Mẫu thử dương tính (IOC bài báo): Đạt ${ver.positive_probes_passed || 0} / ${ver.positive_probes_total || 0}`,
        `Mẫu thử âm tính (Telemetry sạch 8.8.8.8 / google.com): ${ver.negative_probe_passed ? 'KHÔNG BÁO NHẦM (PASS)' : 'CHƯA ĐẠT'}`,
    ];
    (ver.probe_results || []).forEach(p => {
        lines.push(`  • Probe [${p.probe_type}] ${p.expected_value} => ${p.passed ? 'BẮT TRÚNG' : 'TRƯỢT'}`);
    });
    box.innerHTML = lines.map(l => `<div class="reasoning-step">${escapeHtml(l)}</div>`).join('');
}

async function verifyCurrentSkillSandbox() {
    if (!state.currentSkill) return;
    try {
        const res = await fetch('/api/skills/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                skill_name: state.currentSkill.skill_name,
                execution_code: state.currentSkill.execution_code || '',
                iocs_embedded: state.currentSkill.iocs_embedded || {},
            }),
        });
        const data = await res.json();
        renderSandboxVerification(data.verification);
        showToast(`Kiểm chứng Sandbox: ${data.verification.execution_status}`);
    } catch (err) {
        showToast('Lỗi khi kiểm chứng sandbox.');
    }
}

async function loadCorpusList() {
    try {
        const res = await fetch('/api/corpus');
        const data = await res.json();
        state.corpus = data.articles || [];
        document.getElementById('lblCorpusCounter').textContent = `${data.human_verified_count || 0}/${data.total_articles || 0} đã duyệt`;
        renderCorpusList();
    } catch (err) {
        console.error('Corpus load failed:', err);
    }
}

function renderCorpusList() {
    const container = document.getElementById('corpusArticleList');
    if (!state.corpus.length) {
        container.innerHTML = '<div class="details-empty"><p>Chưa có tập 50 bài. Hãy bấm "Cập Nhật Corpus 50 Bài".</p></div>';
        return;
    }
    container.innerHTML = state.corpus.map(item => {
        const active = state.selectedCorpusArticle && state.selectedCorpusArticle.article_id === item.article_id;
        const isVer = item.status === 'human_verified';
        const badge = isVer
            ? `<span class="badge badge-verified">ĐÃ DUYỆT (${escapeHtml(item.annotated_by)})</span>`
            : '<span class="badge badge-pending">CHƯA DUYỆT</span>';
        return `
            <div class="threat-card ${active ? 'active' : ''}" data-article-id="${escapeHtml(item.article_id)}">
                <div class="threat-card-top">
                    <span class="badge badge-vendor">${escapeHtml(item.article_id)} • ${escapeHtml(item.source)}</span>
                    ${badge}
                </div>
                <div class="threat-card-title">${escapeHtml(item.title)}</div>
                <div class="threat-card-meta">
                    <span>${escapeHtml(item.char_length)} ký tự</span>
                    <span>Đáp án tay: ${escapeHtml(item.gt_ioc_count)} IOC</span>
                </div>
            </div>
        `;
    }).join('');
}

async function loadCorpusArticleDetail(articleId) {
    try {
        const res = await fetch(`/api/corpus/${encodeURIComponent(articleId)}`);
        const data = await res.json();
        if (!res.ok) return;

        const art = data.article;
        state.selectedCorpusArticle = art;
        state.selectedRegexHints = data.regex_suggestions;
        renderCorpusList();

        document.getElementById('corpusDetailEmpty').classList.add('hidden');
        document.getElementById('corpusDetailActive').classList.remove('hidden');

        document.getElementById('annArticleId').textContent = `${art.article_id} • ${art.source}`;
        const link = document.getElementById('annOriginalUrl');
        link.href = sanitizeUrl(art.url);
        document.getElementById('annTitle').textContent = art.title || '';
        document.getElementById('annRawContent').textContent = art.raw_content || '';

        const gt = art.ground_truth || {};
        document.getElementById('gtIps').value = (gt.ips || []).join('\n');
        document.getElementById('gtDomains').value = (gt.domains || []).join('\n');
        document.getElementById('gtSha256').value = (gt.sha256 || []).join('\n');
        document.getElementById('gtMd5').value = (gt.md5 || []).join('\n');
        document.getElementById('gtCves').value = (gt.cves || []).join('\n');
        document.getElementById('gtMalware').value = [...(gt.threat_actors || []), ...(gt.malware_families || [])].join(', ');

        const meta = art.annotation_meta || {};
        if (meta.annotated_by) document.getElementById('annReviewerSelect').value = meta.annotated_by;
        document.getElementById('annNotesInput').value = meta.notes || '';
    } catch (err) {
        showToast('Không thể tải chi tiết bài viết.');
    }
}

function prefillRegexHints() {
    if (!state.selectedRegexHints) return;
    const h = state.selectedRegexHints;
    document.getElementById('gtIps').value = (h.ips || []).join('\n');
    document.getElementById('gtDomains').value = (h.domains || []).join('\n');
    document.getElementById('gtSha256').value = (h.sha256 || []).join('\n');
    document.getElementById('gtMd5').value = (h.md5 || []).join('\n');
    document.getElementById('gtCves').value = (h.cves || []).join('\n');
    document.getElementById('gtMalware').value = [...(h.threat_actors || []), ...(h.malware_families || [])].join(', ');
    showToast('Đã điền gợi ý Regex — hãy đọc kỹ bài để xóa domain nhiễu trước khi Lưu!');
}

function parseLineBox(id) {
    return (document.getElementById(id).value || '')
        .split(/[\n,]+/)
        .map(s => s.trim())
        .filter(Boolean);
}

async function saveAnnotation() {
    if (!state.selectedCorpusArticle) return;
    const aid = state.selectedCorpusArticle.article_id;
    const reviewer = document.getElementById('annReviewerSelect').value;
    const notes = document.getElementById('annNotesInput').value.trim();
    const malwareRaw = (document.getElementById('gtMalware').value || '').split(',').map(s => s.trim()).filter(Boolean);

    const payload = {
        annotated_by: reviewer,
        ips: parseLineBox('gtIps'),
        domains: parseLineBox('gtDomains'),
        sha256: parseLineBox('gtSha256'),
        md5: parseLineBox('gtMd5'),
        cves: parseLineBox('gtCves'),
        malware_families: malwareRaw,
        notes,
    };

    try {
        const res = await fetch(`/api/corpus/${encodeURIComponent(aid)}/annotate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.detail || 'Lưu thất bại');
            return;
        }
        showToast(data.message);
        await Promise.all([loadCorpusList(), refreshSystemStatus()]);
    } catch (err) {
        showToast('Lỗi lưu đáp án gán tay.');
    }
}

async function collectCorpus50() {
    const btn = document.getElementById('btnRefreshCorpus');
    btn.disabled = true;
    btn.textContent = 'Đang kéo 50 bài...';
    try {
        const res = await fetch('/api/corpus/collect?limit=50', { method: 'POST' });
        const data = await res.json();
        showToast(data.message);
        await Promise.all([loadCorpusList(), refreshSystemStatus()]);
    } catch (err) {
        showToast('Lỗi cập nhật corpus.');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Cập Nhật Corpus 50 Bài';
    }
}

async function runBenchmark() {
    const btn = document.getElementById('btnRunBenchmark');
    const useHybrid = document.getElementById('chkIncludeHybrid').checked;
    const modes = useHybrid ? ['regex_only', 'hybrid'] : ['regex_only'];

    btn.disabled = true;
    btn.textContent = useHybrid ? 'Đang chấm Agent (có thể mất 1-2 phút)...' : 'Đang chấm Regex...';

    try {
        const res = await fetch('/api/benchmark/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ modes, include_pending: false }),
        });
        const data = await res.json();
        renderBenchmarkResults(data.results);
        showToast(`Đã chấm xong trên ${data.results.verified_articles_evaluated} bài đã gán tay.`);
    } catch (err) {
        showToast('Lỗi chạy benchmark.');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Chạy Chấm Điểm Agent';
    }
}

async function loadLatestBenchmark() {
    try {
        const res = await fetch('/api/benchmark/latest');
        const data = await res.json();
        if (data.status === 'success' && data.results) {
            renderBenchmarkResults(data.results);
        }
    } catch (err) {
        console.error(err);
    }
}

function renderBenchmarkResults(results) {
    if (!results) return;
    document.getElementById('benchmarkSummaryMeta').textContent =
        `Đã chấm: ${results.verified_articles_evaluated}/${results.total_corpus_articles} bài gán nhãn tay (${results.evaluated_at_utc})`;

    const body = document.getElementById('benchmarkCompareBody');
    const modes = results.modes || {};
    const rows = Object.entries(modes).map(([modeName, mdata]) => {
        const ov = mdata.overall || {};
        const sk = mdata.skill_metrics || {};
        return `
            <tr>
                <td>${escapeHtml(modeName)}</td>
                <td>${escapeHtml(ov.tp)}</td>
                <td>${escapeHtml(ov.fp)}</td>
                <td>${escapeHtml(ov.fn)}</td>
                <td class="text-cyan">${escapeHtml(ov.precision)}%</td>
                <td class="text-emerald">${escapeHtml(ov.recall)}%</td>
                <td>${escapeHtml(ov.f1)}%</td>
                <td>${escapeHtml(sk.syntax_valid_rate)}% (${escapeHtml(sk.skills_syntax_valid)}/${escapeHtml(sk.skills_generated)})</td>
                <td>${escapeHtml(sk.sandbox_match_rate)}% (${escapeHtml(sk.skills_sandbox_matched)}/${escapeHtml(sk.skills_generated)})</td>
            </tr>
        `;
    });

    body.innerHTML = rows.length ? rows.join('') : '<tr><td colspan="9">Chưa có bài gán nhãn tay nào để chấm.</td></tr>';

    const errBox = document.getElementById('benchmarkErrorBreakdown');
    const primaryMode = modes.hybrid || modes.regex_only;
    if (primaryMode && (primaryMode.article_details || []).length) {
        const errItems = primaryMode.article_details
            .filter(d => d.fp_count > 0 || d.fn_count > 0)
            .slice(0, 10)
            .map(d => {
                const fps = (d.false_positives || []).map(x => `${x.type}:${x.value}`).join(', ');
                const fns = (d.false_negatives || []).map(x => `${x.type}:${x.value}`).join(', ');
                return `<div class="reasoning-step"><strong>${escapeHtml(d.article_id)}</strong> | Bắt thừa (FP): ${escapeHtml(fps || '0')} | Bỏ sót (FN): ${escapeHtml(fns || '0')}</div>`;
            });
        errBox.innerHTML = errItems.length
            ? `<div class="block-label" style="margin-bottom:6px;">PHÂN TÍCH SAI SỐ TRÊN TỪNG BÀI (${escapeHtml(primaryMode.mode)}):</div><div class="reasoning-steps">${errItems.join('')}</div>`
            : '<div class="block-label text-emerald">Không có sai số (FP=0, FN=0) trên tập bài đã gán tay.</div>';
    } else {
        errBox.innerHTML = '';
    }
}

document.addEventListener('DOMContentLoaded', initApp);
