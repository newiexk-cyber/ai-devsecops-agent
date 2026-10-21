// ==============================================================================
// NETWORK SENTINEL // FRONTEND ORCHESTRATION CLIENT (ENTERPRISE EDITION)
// Architecture: Network Intelligence, Explainable AI (XAI) & Dynamic Agent Skills
// ==============================================================================

let allNetworkThreats = [];
let activeThreatId = null;
let selectedTimeWindow = 'all';
let selectedTag = 'ALL';
let currentActiveSkill = null;

document.addEventListener('DOMContentLoaded', () => {
    initTabNavigation();
    initFilterControls();
    loadSmartTriggerStatus();
    loadNetworkThreats();
    loadSkillsCatalog();
    bindActionButtons();
});

// Toast notification helper
function showToast(message) {
    const toast = document.getElementById('appToast');
    const toastText = document.getElementById('toastText');
    if (!toast || !toastText) return;

    toastText.textContent = message;
    toast.classList.remove('hidden');
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 3200);
}

// Escape HTML utility
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ==============================================================================
// 1. PRIMARY TAB NAVIGATION
// ==============================================================================
function initTabNavigation() {
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active'));

            tab.classList.add('active');
            const targetId = tab.getAttribute('data-tab');
            const targetView = document.getElementById(targetId);
            if (targetView) targetView.classList.add('active');
        });
    });
}

// ==============================================================================
// 2. SMART INGESTION TRIGGER STATUS
// ==============================================================================
async function loadSmartTriggerStatus() {
    const bannerBadge = document.getElementById('bannerUrgencyBadge');
    const bannerReason = document.getElementById('bannerReasonText');
    const kpiUrgency = document.getElementById('kpiUrgencyScore');
    const navTriggerBadge = document.getElementById('navTriggerBadge');

    try {
        const res = await fetch('/api/network-intel/trigger-status');
        const data = await res.json();
        if (data.status === 'success' && data.trigger) {
            const tr = data.trigger;
            if (kpiUrgency) kpiUrgency.textContent = `${tr.urgency_score}/100`;

            if (bannerBadge) {
                bannerBadge.textContent = `${tr.urgency_level} URGENCY (${tr.urgency_score}/100)`;
                bannerBadge.className = 'banner-badge ' + (tr.urgency_level === 'CRITICAL' ? 'badge-critical' : 'badge-medium');
            }
            if (bannerReason) {
                bannerReason.textContent = tr.reason;
            }
            if (navTriggerBadge) {
                navTriggerBadge.textContent = tr.urgency_level;
            }
        }
    } catch (err) {
        console.warn('Smart trigger check notice:', err);
    }
}

// ==============================================================================
// 3. NETWORK THREATS TELEMETRY FEED
// ==============================================================================
async function loadNetworkThreats() {
    const cardList = document.getElementById('threatCardList');
    const countLabel = document.getElementById('lblThreatCounter');
    const navCount = document.getElementById('navThreatCount');
    const kpiCrit = document.getElementById('kpiCriticalCve');
    const kpiC2 = document.getElementById('kpiActiveC2');

    let url = '/api/network-intel/feeds?';
    if (selectedTimeWindow && selectedTimeWindow !== 'all') {
        url += `time_window=${selectedTimeWindow}&`;
    }
    if (selectedTag && selectedTag !== 'ALL') {
        url += `tag=${encodeURIComponent(selectedTag)}&`;
    }

    try {
        const res = await fetch(url);
        const data = await res.json();
        if (data.status === 'success') {
            allNetworkThreats = data.threats || [];
            
            // Filter by search text if any
            const searchInput = document.getElementById('networkSearchInput');
            const query = searchInput ? searchInput.value.toLowerCase().trim() : '';
            const filtered = query ? allNetworkThreats.filter(t => 
                t.title.toLowerCase().includes(query) ||
                t.identifier.toLowerCase().includes(query) ||
                t.vendor.toLowerCase().includes(query) ||
                (t.target_asset && t.target_asset.toLowerCase().includes(query))
            ) : allNetworkThreats;

            // Update counters
            const totalCount = filtered.length;
            if (countLabel) countLabel.textContent = `${totalCount} records`;
            if (navCount) navCount.textContent = totalCount;

            // Update KPI metrics
            const critCount = allNetworkThreats.filter(t => t.severity === 'CRITICAL').length;
            const c2Count = allNetworkThreats.filter(t => t.threat_type === 'C2_IP').length;
            if (kpiCrit) kpiCrit.textContent = critCount;
            if (kpiC2) kpiC2.textContent = c2Count;

            renderThreatCardList(filtered);

            // Auto-select first threat if none selected
            if (filtered.length > 0 && !activeThreatId) {
                selectThreat(filtered[0].id);
            }
        }
    } catch (err) {
        console.error('Failed to load network threats:', err);
    }
}

function renderThreatCardList(threats) {
    const cardList = document.getElementById('threatCardList');
    if (!cardList) return;

    if (!threats || threats.length === 0) {
        cardList.innerHTML = `
            <div style="padding: 40px 20px; text-align: center; color: var(--text-muted); font-size: 12px;">
                No network threats found matching the current timeline and tag filters.
            </div>
        `;
        return;
    }

    const dateLabels = {
        '24h_emergency': '24H EMERGENCY',
        'active_30d': 'ACTIVE 30D',
        'trending_1y': 'PAST 1Y',
        'historical_3y': '1-3Y BASE'
    };

    cardList.innerHTML = threats.map(t => {
        const isEmer = t.date_category === '24h_emergency';
        const isCrit = t.severity === 'CRITICAL';
        const isActive = t.id === activeThreatId ? 'active' : '';

        return `
            <div class="threat-feed-card ${isActive}" data-id="${t.id}" onclick="selectThreat('${t.id}')">
                <div class="card-row-top">
                    <div class="card-badges">
                        <span class="badge ${isCrit ? 'badge-crimson' : 'badge-amber'}">${escapeHtml(t.severity)}</span>
                        <span class="badge ${isEmer ? 'badge-emergency' : 'badge-date'}">${dateLabels[t.date_category] || t.date_category}</span>
                    </div>
                    <span class="card-id-text">${escapeHtml(t.identifier)}</span>
                </div>
                <div class="card-title-text">${escapeHtml(t.title)}</div>
                <div class="card-asset-text">${escapeHtml(t.target_asset)}</div>
                <div class="card-desc-text">${escapeHtml(t.description)}</div>
                <div class="card-date-meta">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
                        <line x1="16" y1="2" x2="16" y2="6"></line>
                        <line x1="8" y1="2" x2="8" y2="6"></line>
                        <line x1="3" y1="10" x2="21" y2="10"></line>
                    </svg>
                    <span>Ngày công bố: <strong>${escapeHtml(t.published_date || t.last_seen || 'N/A')}</strong></span>
                </div>
            </div>
        `;
    }).join('');
}

// ==============================================================================
// 4. INSPECT & GENERATE EXPLAINABLE AI & AGENT SKILL
// ==============================================================================
async function selectThreat(threatId) {
    activeThreatId = threatId;

    // Highlight card
    document.querySelectorAll('.threat-feed-card').forEach(card => {
        if (card.getAttribute('data-id') === threatId) {
            card.classList.add('active');
        } else {
            card.classList.remove('active');
        }
    });

    const emptyState = document.getElementById('detailsEmptyState');
    const content = document.getElementById('detailsActiveContent');

    try {
        const res = await fetch('/api/network-intel/generate-skill', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ threat_id: threatId })
        });

        const data = await res.json();
        if (data.status === 'success') {
            currentActiveSkill = data;
            renderThreatDetailsView(data);
            if (emptyState) emptyState.classList.add('hidden');
            if (content) content.classList.remove('hidden');
        }
    } catch (err) {
        console.error('Failed to generate XAI and Agent Skill:', err);
        showToast('Error connecting to Agent Skill Engine');
    }
}

function renderThreatDetailsView(data) {
    const threat = data.threat || {};
    const xai = data.xai_trust || {};
    const skill = data.agent_skill || {};

    // 1. Overview header
    const sevBadge = document.getElementById('ovSeverityBadge');
    if (sevBadge) {
        sevBadge.textContent = threat.severity || 'CRITICAL';
        sevBadge.className = 'badge ' + (threat.severity === 'CRITICAL' ? 'badge-crimson' : 'badge-amber');
    }
    const dateBadge = document.getElementById('ovDateBadge');
    if (dateBadge) {
        dateBadge.textContent = (threat.date_category || 'ACTIVE').toUpperCase().replace('_', ' ');
    }
    const vendorBadge = document.getElementById('ovVendorBadge');
    if (vendorBadge) vendorBadge.textContent = (threat.vendor || 'NETWORK').toUpperCase();

    const idEl = document.getElementById('ovIdentifier');
    if (idEl) idEl.textContent = threat.identifier || '';

    const titleEl = document.getElementById('ovTitle');
    if (titleEl) titleEl.textContent = threat.title || '';

    const assetEl = document.getElementById('ovTargetAsset');
    if (assetEl) assetEl.textContent = threat.target_asset || '';

    const protoEl = document.getElementById('ovProtocol');
    if (protoEl) protoEl.textContent = threat.protocol || 'TCP/IP';

    const cvssEl = document.getElementById('ovCvss');
    if (cvssEl) cvssEl.textContent = threat.cvss_score || 'N/A';

    const pubDateEl = document.getElementById('ovPublishedDate');
    if (pubDateEl) pubDateEl.textContent = threat.published_date || threat.last_seen || 'N/A';

    const tagsList = document.getElementById('ovTagsList');
    if (tagsList && threat.tags) {
        tagsList.innerHTML = threat.tags.map(tag => `<span class="tag-pill-sm">${escapeHtml(tag)}</span>`).join('');
    }

    // 2. XAI Trust Report
    const trustBadge = document.getElementById('xaiTrustBadge');
    if (trustBadge) {
        trustBadge.textContent = `${xai.trust_score}% TRUST CONFIDENCE (${xai.trust_level})`;
    }

    const stepsList = document.getElementById('xaiStepsList');
    if (stepsList && xai.reasoning_chain) {
        stepsList.innerHTML = xai.reasoning_chain.map(step => `
            <div class="step-item">${escapeHtml(step)}</div>
        `).join('');
    }

    const evidenceList = document.getElementById('xaiEvidenceList');
    if (evidenceList && xai.evidence_sources) {
        evidenceList.innerHTML = xai.evidence_sources.map(ev => `
            <span class="evidence-pill">${escapeHtml(ev)}</span>
        `).join('');
    }

    const blastRadiusBox = document.getElementById('xaiBlastRadiusBox');
    if (blastRadiusBox) {
        blastRadiusBox.textContent = xai.network_blast_radius || 'Perimeter Gateway / Connected Internal Subnets';
    }

    // 3. Dynamic Agent Skill
    const skillNameEl = document.getElementById('lblSkillName');
    if (skillNameEl) skillNameEl.textContent = skill.skill_name || 'custom_network_skill';

    const targetDevicesEl = document.getElementById('lblTargetDevices');
    if (targetDevicesEl && skill.target_devices) {
        targetDevicesEl.textContent = `Supports: ${skill.target_devices.join(', ')}`;
    }

    const schemaDisplay = document.getElementById('codeSchemaDisplay');
    if (schemaDisplay) {
        const toolDefinition = {
            type: "function",
            function: {
                name: skill.skill_name,
                description: skill.description,
                parameters: skill.parameters
            }
        };
        schemaDisplay.textContent = JSON.stringify(toolDefinition, null, 2);
    }

    const pythonDisplay = document.getElementById('codePythonDisplay');
    if (pythonDisplay) {
        pythonDisplay.textContent = skill.execution_code || '# No execution code generated';
    }

    const verifEl = document.getElementById('lblVerificationStep');
    if (verifEl) verifEl.textContent = skill.verification_step || 'Preflight probe';

    const rollbackEl = document.getElementById('lblRollbackSkill');
    if (rollbackEl) rollbackEl.textContent = skill.rollback_skill || 'None';
}

// ==============================================================================
// 5. AGENT SKILLS LIBRARY VIEW (TAB 2)
// ==============================================================================
async function loadSkillsCatalog() {
    const grid = document.getElementById('skillsCatalogGrid');
    if (!grid) return;

    try {
        const res = await fetch('/api/network-intel/skills-library');
        const data = await res.json();
        if (data.status === 'success' && data.skills) {
            grid.innerHTML = data.skills.map(sk => `
                <div class="skill-catalog-item">
                    <div class="catalog-item-header">
                        <span class="catalog-skill-title">${escapeHtml(sk.skill_name)}</span>
                        <span class="catalog-category-tag">${escapeHtml(sk.category)}</span>
                    </div>
                    <div class="catalog-skill-desc">${escapeHtml(sk.summary)}</div>
                    <div class="catalog-targets-row">
                        <strong>Target Infrastructure:</strong> ${(sk.target_types || []).join(', ')}
                    </div>
                </div>
            `).join('');
        }
    } catch (err) {
        console.warn('Failed to load skills catalog:', err);
    }
}

// ==============================================================================
// 6. FILTER CONTROLS & EVENT BINDINGS
// ==============================================================================
function initFilterControls() {
    // Timeline segmented buttons
    const timelineButtons = document.querySelectorAll('#timelineFilterGroup .segment-btn');
    timelineButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            timelineButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            selectedTimeWindow = btn.getAttribute('data-window');
            loadNetworkThreats();
        });
    });

    // Tag pills
    const tagButtons = document.querySelectorAll('#tagsFilterGroup .tag-pill');
    tagButtons.forEach(pill => {
        pill.addEventListener('click', () => {
            tagButtons.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            selectedTag = pill.getAttribute('data-tag');
            loadNetworkThreats();
        });
    });

    // Search input
    const searchInput = document.getElementById('networkSearchInput');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            loadNetworkThreats();
        });
    }

    // Code container view toggle (Schema vs Python code)
    const codeTabButtons = document.querySelectorAll('.code-tab-btn');
    codeTabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            codeTabButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const target = btn.getAttribute('data-target');
            document.querySelectorAll('.code-pre').forEach(pre => pre.classList.remove('active'));
            const targetPre = document.getElementById(target);
            if (targetPre) targetPre.classList.add('active');
        });
    });
}

function bindActionButtons() {
    // Copy Tool Schema Button
    const btnCopySchema = document.getElementById('btnCopyToolSchema');
    if (btnCopySchema) {
        btnCopySchema.addEventListener('click', () => {
            if (!currentActiveSkill || !currentActiveSkill.agent_skill) {
                showToast('No active Agent Skill loaded to copy');
                return;
            }
            const toolDef = {
                type: "function",
                function: {
                    name: currentActiveSkill.agent_skill.skill_name,
                    description: currentActiveSkill.agent_skill.description,
                    parameters: currentActiveSkill.agent_skill.parameters
                }
            };
            navigator.clipboard.writeText(JSON.stringify(toolDef, null, 2)).then(() => {
                showToast('Agent Skill JSON Schema copied to clipboard');
            }).catch(() => {
                showToast('Failed to copy schema');
            });
        });
    }

    // Generic Active Crawl Trigger Helper
    const executeActiveCrawl = async (endpoint, btnElement, loadingText) => {
        const originalHtml = btnElement ? btnElement.innerHTML : '';
        if (btnElement) {
            btnElement.disabled = true;
            btnElement.innerHTML = `
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin">
                    <circle cx="12" cy="12" r="10"></circle>
                    <path d="M12 2a10 10 0 0 1 10 10"></path>
                </svg>
                ${loadingText}...
            `;
        }

        try {
            showToast(`${loadingText}...`);
            const res = await fetch(endpoint, { method: 'POST' });
            const data = await res.json();
            if (data.status === 'success') {
                showToast(data.message || 'Cào dữ liệu thành công!');
                // Reset filter to All so newly crawled threats appear immediately
                selectedTimeWindow = 'all';
                selectedTag = 'ALL';
                document.querySelectorAll('#timelineFilterGroup .segment-btn').forEach(b => {
                    b.classList.toggle('active', b.getAttribute('data-window') === 'all');
                });
                document.querySelectorAll('#tagsFilterGroup .tag-pill').forEach(b => {
                    b.classList.toggle('active', b.getAttribute('data-tag') === 'ALL');
                });

                await loadSmartTriggerStatus();
                await loadNetworkThreats();
                if (allNetworkThreats.length > 0) {
                    selectThreat(allNetworkThreats[0].id);
                }
            } else {
                showToast(data.detail || 'Lỗi khi kết nối nguồn cào');
            }
        } catch (err) {
            console.error('Crawler error:', err);
            showToast('Lỗi kết nối tới nguồn tin an ninh mạng');
        } finally {
            if (btnElement) {
                btnElement.disabled = false;
                btnElement.innerHTML = originalHtml;
            }
        }
    };

    // 1. Button: Cào CISA KEV (Web & Network CVEs)
    const btnCrawlCisa = document.getElementById('btnCrawlCisaKev');
    if (btnCrawlCisa) {
        btnCrawlCisa.addEventListener('click', () => {
            executeActiveCrawl('/api/crawler/cisa-kev', btnCrawlCisa, 'Đang cào CISA KEV Catalog');
        });
    }

    // 2. Button: Cào Whitelist Feeds (The Hacker News & BleepingComputer)
    const btnCrawlRss = document.getElementById('btnCrawlWhitelistRss');
    if (btnCrawlRss) {
        btnCrawlRss.addEventListener('click', () => {
            executeActiveCrawl('/api/crawler/whitelist-rss', btnCrawlRss, 'Đang cào The Hacker News & BleepingComputer');
        });
    }

    // 3. Button: Cào Toàn Bộ Nguồn Whitelist (Sync All)
    const btnCrawlAll = document.getElementById('btnCrawlAllWhitelist');
    if (btnCrawlAll) {
        btnCrawlAll.addEventListener('click', () => {
            executeActiveCrawl('/api/crawler/sync-all', btnCrawlAll, 'Đang cào toàn bộ Whitelist Sources');
        });
    }

    // Header & Smart Banner Quick Sync buttons
    const handleTriggerSync = () => {
        executeActiveCrawl('/api/crawler/sync-all', null, 'Đang đồng bộ telemetry từ Whitelist');
    };

    const btnHeaderSync = document.getElementById('btnHeaderSmartSync');
    if (btnHeaderSync) btnHeaderSync.addEventListener('click', handleTriggerSync);

    const btnSmartBanner = document.getElementById('btnSmartTriggerAction');
    if (btnSmartBanner) btnSmartBanner.addEventListener('click', handleTriggerSync);

    const btnManualEval = document.getElementById('btnManualTriggerEval');
    if (btnManualEval) btnManualEval.addEventListener('click', handleTriggerSync);

    // 4. On-Demand Direct CVE Ingestion Handler
    const handleOnDemandIngest = async (cveId) => {
        if (!cveId || !cveId.trim()) {
            showToast('Vui lòng nhập mã CVE mạng hợp lệ (vd: CVE-2024-24919)');
            return;
        }
        const cleanId = cveId.trim().toUpperCase();
        const btnSubmit = document.getElementById('btnSubmitOnDemandCve');
        const inputEl = document.getElementById('inputOnDemandCve');
        const originalText = btnSubmit ? btnSubmit.innerHTML : '';

        if (btnSubmit) {
            btnSubmit.disabled = true;
            btnSubmit.innerHTML = `
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin">
                    <circle cx="12" cy="12" r="10"></circle>
                    <path d="M12 2a10 10 0 0 1 10 10"></path>
                </svg>
                Kéo về...
            `;
        }

        try {
            const res = await fetch('/api/network-intel/ingest-cve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cve_id: cleanId })
            });
            const data = await res.json();
            if (data.status === 'success' && data.threat) {
                showToast(`Đã cào thành công ${data.threat.identifier} & sinh Dynamic Agent Skill!`);
                if (inputEl) inputEl.value = '';
                
                selectedTimeWindow = 'all';
                selectedTag = 'ALL';
                document.querySelectorAll('#timelineFilterGroup .segment-btn').forEach(b => {
                    b.classList.toggle('active', b.getAttribute('data-window') === 'all');
                });
                document.querySelectorAll('#tagsFilterGroup .tag-pill').forEach(b => {
                    b.classList.toggle('active', b.getAttribute('data-tag') === 'ALL');
                });

                await loadNetworkThreats();
                await loadSmartTriggerStatus();
                selectThreat(data.threat.id);
            } else {
                showToast(data.detail || 'Không thể cào thông tin CVE này');
            }
        } catch (err) {
            console.error('Error on-demand ingest:', err);
            showToast('Lỗi khi cào dữ liệu CVE');
        } finally {
            if (btnSubmit) {
                btnSubmit.disabled = false;
                btnSubmit.innerHTML = originalText;
            }
        }
    };

    const btnSubmitCve = document.getElementById('btnSubmitOnDemandCve');
    const inputCve = document.getElementById('inputOnDemandCve');
    if (btnSubmitCve && inputCve) {
        btnSubmitCve.addEventListener('click', () => {
            handleOnDemandIngest(inputCve.value);
        });
        inputCve.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                handleOnDemandIngest(inputCve.value);
            }
        });
    }

    // Quick crawl chips
    document.querySelectorAll('.cve-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            const cve = chip.getAttribute('data-cve');
            if (inputCve) inputCve.value = cve;
            handleOnDemandIngest(cve);
        });
    });
}


