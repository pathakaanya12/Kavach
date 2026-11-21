// KAVACH Frontend Controller - Team अपराजित

let currentState = {};
let currentEmails = [];
let lastEventCount = 0;
let pollTimer = null;
let currentPendingApprovalId = null;

// DOM Elements
const switchToggleBtn = document.getElementById("switchToggleBtn");
const switchKnob = document.getElementById("switchKnob");
const switchLabel = document.getElementById("switchLabel");
const runBtn = document.getElementById("runBtn");
const redteamBtn = document.getElementById("redteamBtn");
const resetBtn = document.getElementById("resetBtn");
const killBtn = document.getElementById("killBtn");
const pinToolsBtn = document.getElementById("pinToolsBtn");
const variantSelect = document.getElementById("variantSelect");
const emailList = document.getElementById("emailList");
const timelineContainer = document.getElementById("timelineContainer");
const auditTableBody = document.getElementById("auditTableBody");
const auditIntegrityBadge = document.getElementById("auditIntegrityBadge");
const refreshAuditBtn = document.getElementById("refreshAuditBtn");
const statusPill = document.getElementById("statusPill");
const plannerModeLabel = document.getElementById("plannerModeLabel");
const guardStatusLabel = document.getElementById("guardStatusLabel");

// Modals
const approvalModal = document.getElementById("approvalModal");
const apprTool = document.getElementById("apprTool");
const apprArgs = document.getElementById("apprArgs");
const apprReason = document.getElementById("apprReason");
const apprPolicy = document.getElementById("apprPolicy");
const apprHiddenWrap = document.getElementById("apprHiddenWrap");
const apprHidden = document.getElementById("apprHidden");
const modalAllowBtn = document.getElementById("modalAllowBtn");
const modalBlockBtn = document.getElementById("modalBlockBtn");

// Live Gmail Elements
const openGmailModalBtn = document.getElementById("openGmailModalBtn");
const resetInboxBtn = document.getElementById("resetInboxBtn");
const gmailModal = document.getElementById("gmailModal");
const closeGmailModalBtn = document.getElementById("closeGmailModalBtn");
const cancelGmailBtn = document.getElementById("cancelGmailBtn");
const fetchGmailSubmitBtn = document.getElementById("fetchGmailSubmitBtn");
const fetchGmailSpinner = document.getElementById("fetchGmailSpinner");
const fetchGmailBtnText = document.getElementById("fetchGmailBtnText");
const liveGmailInput = document.getElementById("liveGmailInput");
const liveGmailPwdInput = document.getElementById("liveGmailPwdInput");
const liveGmailLimitSelect = document.getElementById("liveGmailLimitSelect");
const gmailFeedback = document.getElementById("gmailFeedback");
const inboxCount = document.getElementById("inboxCount");

// Modal Security Banner Elements
const modalSecurityBanner = document.getElementById("modalSecurityBanner");
const modalSecurityIcon = document.getElementById("modalSecurityIcon");
const modalSecurityVerdict = document.getElementById("modalSecurityVerdict");
const modalSecurityReason = document.getElementById("modalSecurityReason");
const modalSecurityTag = document.getElementById("modalSecurityTag");

const emailModal = document.getElementById("emailModal");
const modalEmailSubject = document.getElementById("modalEmailSubject");
const modalEmailFrom = document.getElementById("modalEmailFrom");
const modalEmailBody = document.getElementById("modalEmailBody");
const closeEmailModalBtn = document.getElementById("closeEmailModalBtn");

// Outcome Overlay
const outcomeOverlay = document.getElementById("outcomeOverlay");
const outcomeCard = document.getElementById("outcomeCard");
const outcomeHeading = document.getElementById("outcomeHeading");
const outcomeSubtext = document.getElementById("outcomeSubtext");
const outcomeDetails = document.getElementById("outcomeDetails");
const outcomeIconContainer = document.getElementById("outcomeIconContainer");
const dismissOverlayBtn = document.getElementById("dismissOverlayBtn");

// True once the user dismisses the end of run overlay for the current run.
// Without this flag, the 500 ms state poll reopens the overlay right after
// dismiss, because the run status stays breached or protected.
let outcomeDismissed = false;

// Initialize
async function init() {
  bindEvents();
  await fetchEmails();
  await pollState();
  await loadPermissions();
  await loadToolScan();
  await fetchAudit();
  pollTimer = setInterval(pollState, 500);
}

function bindEvents() {
  switchToggleBtn.addEventListener("click", toggleKavachSwitch);
  runBtn.addEventListener("click", startDemoRun);
  if (redteamBtn) redteamBtn.addEventListener("click", startRedteam);
  resetBtn.addEventListener("click", resetRun);
  if (killBtn) killBtn.addEventListener("click", killRun);
  if (pinToolsBtn) pinToolsBtn.addEventListener("click", pinTools);
  variantSelect.addEventListener("change", fetchEmails);
  refreshAuditBtn.addEventListener("click", fetchAudit);

  modalAllowBtn.addEventListener("click", () => submitApprovalDecision("allow"));
  modalBlockBtn.addEventListener("click", () => submitApprovalDecision("block"));

  closeEmailModalBtn.addEventListener("click", () => {
    emailModal.classList.add("hidden");
  });

  dismissOverlayBtn.addEventListener("click", () => {
    outcomeDismissed = true;
    outcomeOverlay.classList.add("hidden");
  });

  if (openGmailModalBtn) {
    openGmailModalBtn.addEventListener("click", () => {
      gmailModal.classList.remove("hidden");
      gmailFeedback.classList.add("hidden");
      refreshLiveGmailConfig();
    });
  }

  if (closeGmailModalBtn) {
    closeGmailModalBtn.addEventListener("click", () => {
      gmailModal.classList.add("hidden");
    });
  }

  if (cancelGmailBtn) {
    cancelGmailBtn.addEventListener("click", () => {
      gmailModal.classList.add("hidden");
    });
  }

  if (fetchGmailSubmitBtn) {
    fetchGmailSubmitBtn.addEventListener("click", handleLiveGmailFetch);
  }

  if (resetInboxBtn) {
    resetInboxBtn.addEventListener("click", handleResetInbox);
  }
}

async function refreshLiveGmailConfig() {
  try {
    const res = await fetch("/api/emails/live-config");
    const cfg = await res.json();
    const hint = document.getElementById("liveGmailEnvHint");
    if (hint) {
      hint.textContent = cfg.configured
        ? `Account saved in .env: ${cfg.address_masked} - leave both fields empty to use it.`
        : "No account in .env. Fill both fields, or add GMAIL_ADDRESS and GMAIL_APP_PASSWORD to .env.";
    }
  } catch (e) { /* ignore */ }
}

async function handleLiveGmailFetch() {
  const email = liveGmailInput.value.trim();
  const appPwd = liveGmailPwdInput.value.trim();
  const limit = parseInt(liveGmailLimitSelect ? liveGmailLimitSelect.value : "8", 10) || 8;

  // Both empty -> server uses the account saved in .env (GMAIL_ADDRESS / GMAIL_APP_PASSWORD)
  if ((email && !appPwd) || (!email && appPwd)) {
    showGmailFeedback("Either fill both Gmail address and App Password, or leave both empty to use the account from .env.", "error");
    return;
  }

  fetchGmailSpinner.classList.remove("hidden");
  fetchGmailBtnText.textContent = "Connecting & Screening...";
  fetchGmailSubmitBtn.disabled = true;
  gmailFeedback.classList.add("hidden");

  try {
    const res = await fetch("/api/emails/live-fetch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email, app_password: appPwd, limit: limit, set_as_inbox: true })
    });
    const data = await res.json();

    if (data.status === "success") {
      showGmailFeedback(`✓ Successfully connected! Fetched & screened ${data.count} live emails from Gmail.`, "success");
      currentEmails = data.emails;
      renderEmails();
      if (resetInboxBtn) resetInboxBtn.classList.remove("hidden");
      setTimeout(() => {
        gmailModal.classList.add("hidden");
      }, 1500);
    } else {
      let msg = `<strong>Connection Error:</strong> ${escapeHtml(data.error || "Authentication failed")}<br><br>`;
      if (data.hints && data.hints.length) {
        msg += `<div class='space-y-1 mt-1'>${data.hints.map(h => `<div>${escapeHtml(h)}</div>`).join('')}</div>`;
      }
      showGmailFeedback(msg, "error");
    }
  } catch (err) {
    showGmailFeedback(`Network or Server error: ${err.message}`, "error");
  } finally {
    fetchGmailSpinner.classList.add("hidden");
    fetchGmailBtnText.textContent = "Fetch & Screen Live";
    fetchGmailSubmitBtn.disabled = false;
  }
}

async function handleResetInbox() {
  try {
    await fetch("/api/emails/reset-inbox", { method: "POST" });
    if (resetInboxBtn) resetInboxBtn.classList.add("hidden");
    await fetchEmails();
  } catch (err) {
    console.error("Failed to reset inbox", err);
  }
}

function showGmailFeedback(htmlContent, type) {
  gmailFeedback.innerHTML = htmlContent;
  gmailFeedback.classList.remove("hidden", "bg-red-950/60", "border-red-500/50", "text-red-300", "bg-emerald-950/60", "border-emerald-500/50", "text-emerald-300");
  if (type === "success") {
    gmailFeedback.classList.add("bg-emerald-950/60", "border", "border-emerald-500/50", "text-emerald-300");
  } else {
    gmailFeedback.classList.add("bg-red-950/60", "border", "border-red-500/50", "text-red-300");
  }
}

// Fetch and Render Emails
async function fetchEmails() {
  const variant = variantSelect.value;
  try {
    const res = await fetch(`/api/emails?variant=${variant}`);
    currentEmails = await res.json();
    renderEmails();
  } catch (err) {
    console.error("Failed to load emails", err);
  }
}

function renderEmails() {
  if (inboxCount) inboxCount.textContent = currentEmails.length;
  emailList.innerHTML = "";

  currentEmails.forEach((email) => {
    // An email is unsafe if it is flagged by Lock 1 screening or marked poisoned
    const isUnsafe = (email.screen_result === "flag" || email.screen_result === "flagged" || email.poisoned === true);
    // Show security verdict if Kavach is ON, or if email was already screened (like Live Gmail or loaded with verdict)
    const showSecurityStatus = currentState.switch || (email.screen_result !== undefined);

    const card = document.createElement("div");
    card.className = `p-3.5 rounded-xl border cursor-pointer transition-all ${
      isUnsafe && showSecurityStatus
        ? "bg-red-950/30 border-red-500/60 hover:border-red-400 hover:bg-red-950/40 shadow-sm shadow-red-500/10"
        : showSecurityStatus
        ? "bg-slate-800/70 border-emerald-500/30 hover:border-emerald-500/60 hover:bg-slate-800"
        : "bg-slate-800/60 border-slate-700/60 hover:bg-slate-800 hover:border-slate-600"
    }`;

    // Prominent Hindi/English Status Badge
    let badgeHtml = "";
    if (showSecurityStatus) {
      if (isUnsafe) {
        badgeHtml = `
          <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/40 flex items-center space-x-1 animate-pulse">
            <span>🚨</span>
            <span>THEEK NAHI (FLAGGED)</span>
          </span>
        `;
      } else {
        badgeHtml = `
          <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1">
            <span>✓</span>
            <span>THEEK HAI (SAFE)</span>
          </span>
        `;
      }
    } else {
      badgeHtml = `<span class="text-[10px] text-slate-500 font-mono">#${email.id}</span>`;
    }

    // Reason line preview
    let reasonLine = "";
    if (email.screen_reason && showSecurityStatus) {
      const textColor = isUnsafe ? "text-red-400" : "text-emerald-400/90";
      reasonLine = `<div class="text-[10px] ${textColor} font-mono mt-1 truncate">🛡️ ${escapeHtml(email.screen_reason)}</div>`;
    }

    const cleanPreview = escapeHtml(email.body.replace(/<!--[\s\S]*?-->/g, "[Hidden Attachment]"));

    card.innerHTML = `
      <div class="flex items-center justify-between mb-1.5 gap-2">
        <span class="text-xs text-slate-300 font-medium truncate max-w-[160px]" title="${escapeHtml(email.from)}">${escapeHtml(email.from)}</span>
        ${badgeHtml}
      </div>
      <h4 class="text-xs font-bold text-slate-100 line-clamp-1">${escapeHtml(email.subject)}</h4>
      ${reasonLine}
      <p class="text-[11px] text-slate-400 mt-1 line-clamp-2 leading-relaxed">${cleanPreview}</p>
      ${email.date ? `<div class="text-[9px] text-slate-500 mt-1.5 text-right font-mono">${escapeHtml(email.date)}</div>` : ''}
    `;

    card.addEventListener("click", () => openEmailInspector(email));
    emailList.appendChild(card);
  });
}

function openEmailInspector(email) {
  modalEmailSubject.textContent = email.subject;
  modalEmailFrom.textContent = `From: ${email.from}` + (email.date ? ` • ${email.date}` : "");

  const isUnsafe = (email.screen_result === "flag" || email.screen_result === "flagged" || email.poisoned === true);
  if (modalSecurityBanner) {
    if (isUnsafe) {
      modalSecurityBanner.className = "mt-3 p-3 rounded-xl border border-red-500/60 bg-red-950/50 flex items-center justify-between";
      modalSecurityIcon.textContent = "🚨";
      modalSecurityVerdict.textContent = "THEEK NAHI HAI (SUSPICIOUS / ATTACK DETECTED)";
      modalSecurityVerdict.className = "font-bold text-xs uppercase tracking-wide text-red-400";
      modalSecurityReason.textContent = email.screen_reason || "Kavach Lock 1 Alert: Is email me hidden prompt injection ya malicious instructions detect hui hain.";
      modalSecurityTag.textContent = "FLAGGED";
      modalSecurityTag.className = "px-2.5 py-1 rounded-full text-[10px] font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse";
    } else {
      modalSecurityBanner.className = "mt-3 p-3 rounded-xl border border-emerald-500/40 bg-emerald-950/40 flex items-center justify-between";
      modalSecurityIcon.textContent = "🟢";
      modalSecurityVerdict.textContent = "THEEK HAI (SAFE ✓ VERIFIED BY KAVACH)";
      modalSecurityVerdict.className = "font-bold text-xs uppercase tracking-wide text-emerald-400";
      modalSecurityReason.textContent = email.screen_reason || "Kavach Lock 1: Clean email. Koi hidden injection, data leak, ya unauthorized prompt nahi mila.";
      modalSecurityTag.textContent = "SAFE ✓";
      modalSecurityTag.className = "px-2.5 py-1 rounded-full text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
    }
  }

  // Highlight hidden HTML comment injection in bright red for the judges
  let bodyHtml = escapeHtml(email.body);
  bodyHtml = bodyHtml.replace(
    /(&lt;!--[\s\S]*?--&gt;)/g,
    `<span class="bg-red-500/20 text-red-400 border border-red-500/50 p-2 rounded-lg block my-2 font-bold shadow-inner pulse-glow">$1</span>`
  );

  modalEmailBody.innerHTML = bodyHtml;
  emailModal.classList.remove("hidden");
}

// Switch Toggle
async function toggleKavachSwitch() {
  const newSwitchState = !currentState.switch;
  try {
    const res = await fetch("/api/switch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ on: newSwitchState })
    });
    const data = await res.json();
    updateSwitchUI(data.switch);
    await fetchAudit();
  } catch (err) {
    console.error("Failed to toggle switch", err);
  }
}

function updateSwitchUI(isOn) {
  if (isOn) {
    switchToggleBtn.classList.remove("bg-slate-700");
    switchToggleBtn.classList.add("bg-emerald-600");
    switchKnob.classList.remove("translate-x-0");
    switchKnob.classList.add("translate-x-8");
    switchLabel.textContent = "KAVACH ON";
    switchLabel.classList.remove("text-slate-400");
    switchLabel.classList.add("text-emerald-400");
    guardStatusLabel.textContent = "SHIELDED";
    guardStatusLabel.className = "text-emerald-400 font-bold";
  } else {
    switchToggleBtn.classList.remove("bg-emerald-600");
    switchToggleBtn.classList.add("bg-slate-700");
    switchKnob.classList.remove("translate-x-8");
    switchKnob.classList.add("translate-x-0");
    switchLabel.textContent = "KAVACH OFF";
    switchLabel.classList.remove("text-emerald-400");
    switchLabel.classList.add("text-slate-400");
    guardStatusLabel.textContent = "UNSHIELDED";
    guardStatusLabel.className = "text-red-400 font-bold";
  }
}

// Red Team
async function startRedteam() {
  try {
    if (redteamBtn) { redteamBtn.disabled = true; redteamBtn.classList.add("opacity-50"); }
    const res = await fetch("/api/redteam", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ n: 20, source: "auto" })
    });
    if (!res.ok) { alert("Red Team busy — wait for the current run to finish."); return; }
    pollRedteam();
  } catch (err) { console.error("Red team start error", err); }
  finally { if (redteamBtn) { redteamBtn.disabled = false; redteamBtn.classList.remove("opacity-50"); } }
}

async function pollRedteam() {
  try {
    const res = await fetch("/api/redteam");
    const data = await res.json();
    renderRedteam(data);
    if (data.status === "running") setTimeout(pollRedteam, 700);
  } catch (err) { console.error("Red team poll error", err); }
}

function renderRedteam(data) {
  const wrap = document.getElementById("redteamProgressWrap");
  const bar = document.getElementById("redteamProgressBar");
  const prog = data.progress || { done: 0, total: 0 };
  if (data.status === "running" && wrap) {
    wrap.classList.remove("hidden");
    bar.style.width = prog.total ? Math.round(100 * prog.done / prog.total) + "%" : "5%";
  } else if (wrap) { wrap.classList.add("hidden"); }
  const r = data.result;
  if (!r || r.error) return;
  document.getElementById("rtTotal").textContent = r.total;
  document.getElementById("rtBlocked").textContent = r.blocked;
  document.getElementById("rtMissed").textContent = r.missed;
  document.getElementById("rtFalse").textContent = r.false_alarms;
  document.getElementById("rtControls").textContent = r.controls;
  document.getElementById("redteamSource").textContent = r.source || "library";
  if (typeof renderRound2 === "function") renderRound2(r);
  const tbody = document.getElementById("redteamTableBody");
  tbody.innerHTML = Object.entries(r.by_category || {}).map(([cat, v]) =>
    `<tr class="border-b border-slate-800/60"><td class="py-1 pr-2">${escapeHtml(cat)}</td><td class="py-1 pr-2">${v.total}</td><td class="py-1">${v.blocked}</td></tr>`).join("");
  const missedEl = document.getElementById("redteamMissed");
  missedEl.innerHTML = (r.missed_items || []).length
    ? "<strong>Missed attacks (fix these in policy next):</strong><br>" + r.missed_items.map(m => `• ${escapeHtml(m.subject)} [${escapeHtml(m.category)}] — ${escapeHtml(m.reason || "")}`).join("<br>")
    : "No missed attacks in this run.";
}

// Run & Reset Actions
async function startDemoRun() {
  outcomeDismissed = false;
  outcomeOverlay.classList.add("hidden");
  const variant = variantSelect.value;
  try {
    runBtn.disabled = true;
    runBtn.classList.add("opacity-50", "cursor-not-allowed");
    await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ variant })
    });
  } catch (err) {
    console.error("Failed to start run", err);
    runBtn.disabled = false;
    runBtn.classList.remove("opacity-50", "cursor-not-allowed");
  }
}

async function resetRun() {
  try {
    outcomeDismissed = false;
    outcomeOverlay.classList.add("hidden");
    await fetch("/api/reset", { method: "POST" });
    timelineContainer.innerHTML = `<div class="text-slate-500 italic p-6 text-center">Ready. Click 'RUN DEMO' to launch.</div>`;
    lastEventCount = 0;
    await pollState();
    await fetchAudit();
  } catch (err) {
    console.error("Failed to reset", err);
  }
}

// V2: Kill Switch + Tool Trust + Least Privilege
async function killRun() {
  try {
    await fetch("/api/kill", { method: "POST" });
    await pollState();
  } catch (err) { console.error("Kill error", err); }
}
async function pinTools() {
  try {
    await fetch("/api/tool-scan/pin", { method: "POST" });
    await loadToolScan();
  } catch (err) { console.error("Pin error", err); }
}
async function loadToolScan() {
  try {
    const res = await fetch("/api/tool-scan");
    const d = await res.json();
    const el = document.getElementById("toolTrustBody");
    if (!el) return;
    const drift = d.drift || {};
    if (!d.baseline_exists) { el.innerHTML = "No baseline pinned yet. Click \u201cPin tools\u201d to hash the current tool definitions."; return; }
    const alarm = d.rug_pull_suspected
      ? "<div class='text-red-400 font-bold'>⚠️ RUG-PULL SUSPECTED — a pinned tool definition changed: " + escapeHtml((drift.changed || []).join(", ")) + "</div>"
      : "<div class='text-emerald-400 font-bold'>✓ No drift — pinned definitions unchanged.</div>";
    el.innerHTML = alarm + "<div class='mt-2'>Pinned tools: " + (d.pinned_count ?? 0) + " · Changed: " + (drift.changed || []).length + " · Added: " + (drift.added || []).length + " · Removed: " + (drift.removed || []).length + "</div>";
  } catch (err) { console.error("Tool-scan load error", err); }
}
async function loadPermissions() {
  try {
    const res = await fetch("/api/permissions");
    const d = await res.json();
    const el = document.getElementById("permissionsBody");
    if (!el) return;
    el.innerHTML = (d.tools || []).map(t =>
      `<div class="flex justify-between py-1 border-b border-slate-800/60"><span>${escapeHtml(t.name)}</span><span>${escapeHtml(t.tier)}${t.needs_approval ? " · needs approval" : " · auto"}</span></div>`
    ).join("") + "<div class='text-slate-500 mt-2'>Destructive + financial tools always need a human.</div>";
  } catch (err) { console.error("Permissions load error", err); }
}

// Approval Handler
async function submitApprovalDecision(decision) {
  if (!currentPendingApprovalId) return;
  try {
    await fetch("/api/approval", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: currentPendingApprovalId, decision })
    });
    approvalModal.classList.add("hidden");
    currentPendingApprovalId = null;
    await pollState();
  } catch (err) {
    console.error("Approval submit error", err);
  }
}

// State Polling
async function pollState() {
  try {
    const res = await fetch("/api/state");
    currentState = await res.json();

    updateSwitchUI(currentState.switch);
    plannerModeLabel.textContent = currentState.planner || "scripted";

    // Update Status Pill
    statusPill.textContent = currentState.status.toUpperCase();

    // Scoreboard + multi-agent lanes
    const sb = currentState.scoreboard || {};
    const sbAttacks = document.getElementById("sbAttacks");
    if (sbAttacks) {
      sbAttacks.textContent = sb.attacks_attempted ?? 0;
      document.getElementById("sbBlocked").textContent = sb.blocked ?? 0;
      document.getElementById("sbLegit").textContent = `${sb.legit_done ?? 0}/${sb.legit_total ?? 2}`;
    }
    const lanes = document.getElementById("multiagentLanes");
    if (lanes) {
      if (currentState.taint_path) {
        lanes.classList.remove("hidden");
        document.getElementById("taintPathText").textContent = currentState.taint_path;
      } else { lanes.classList.add("hidden"); }
    }
    // Red Team result piggy-backed on state
    if (currentState.redteam && currentState.redteam.result) {
      renderRedteam(currentState.redteam);
    }
    if (currentState.status === "running") {
      statusPill.className = "px-2.5 py-1 rounded-full text-xs font-bold uppercase bg-blue-500/20 text-blue-400 border border-blue-500/30 animate-pulse";
      runBtn.disabled = true;
      runBtn.classList.add("opacity-50", "cursor-not-allowed");
    } else if (currentState.status === "waiting_approval") {
      statusPill.className = "px-2.5 py-1 rounded-full text-xs font-bold uppercase bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse";
    } else if (currentState.status === "breached") {
      statusPill.className = "px-2.5 py-1 rounded-full text-xs font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/30";
      runBtn.disabled = false;
      runBtn.classList.remove("opacity-50", "cursor-not-allowed");
    } else if (currentState.status === "killed") {
      statusPill.className = "px-2.5 py-1 rounded-full text-xs font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/30";
      runBtn.disabled = false;
      runBtn.classList.remove("opacity-50", "cursor-not-allowed");
    } else if (currentState.status === "protected") {
      statusPill.className = "px-2.5 py-1 rounded-full text-xs font-bold uppercase bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
      runBtn.disabled = false;
      runBtn.classList.remove("opacity-50", "cursor-not-allowed");
    } else {
      statusPill.className = "px-2.5 py-1 rounded-full text-xs font-bold uppercase bg-slate-800 text-slate-400 border border-slate-700";
      runBtn.disabled = false;
      runBtn.classList.remove("opacity-50", "cursor-not-allowed");
    }

    // Render Events in Timeline
    renderTimeline(currentState.events || []);

    // Check for Pending Human Approval
    if (currentState.pending_approval && currentState.status === "waiting_approval") {
      showApprovalModal(currentState.pending_approval);
    } else {
      approvalModal.classList.add("hidden");
    }

    // Check End Overlays (skip if the user already dismissed this run's overlay)
    if (!outcomeDismissed && currentState.status === "breached" && outcomeOverlay.classList.contains("hidden")) {
      showBreachedOverlay();
    } else if (!outcomeDismissed && currentState.status === "protected" && outcomeOverlay.classList.contains("hidden")) {
      showProtectedOverlay();
    }

    // Re-render emails to update FLAGGED badges
    renderEmails();

  } catch (err) {
    console.error("Polling error", err);
  }
}

function renderTimeline(events) {
  if (events.length === 0) return;
  if (events.length === lastEventCount) return;

  if (lastEventCount === 0) {
    timelineContainer.innerHTML = "";
  }

  for (let i = lastEventCount; i < events.length; i++) {
    const ev = events[i];
    const row = document.createElement("div");
    row.className = "p-2.5 rounded-lg border flex items-start space-x-2.5 text-xs transition-all";

    let borderClass = "border-slate-800 bg-slate-950/60";
    let icon = `<span class="text-blue-400">●</span>`;

    if (ev.type.includes("flagged") || ev.type.includes("breach") || ev.type.includes("block")) {
      borderClass = "border-red-500/40 bg-red-950/20 text-red-200";
      icon = `<span class="text-red-400 font-bold">🛑</span>`;
    } else if (ev.type.includes("ask") || ev.type.includes("approval")) {
      borderClass = "border-amber-500/40 bg-amber-950/20 text-amber-200";
      icon = `<span class="text-amber-400 font-bold">⚠️</span>`;
    } else if (ev.type.includes("safe") || ev.type.includes("allow") || ev.type.includes("execution")) {
      borderClass = "border-emerald-500/40 bg-emerald-950/20 text-emerald-200";
      icon = `<span class="text-emerald-400 font-bold">✓</span>`;
    }

    row.className = `p-2.5 rounded-lg border flex items-start space-x-2.5 text-xs ${borderClass}`;
    row.innerHTML = `
      <div class="mt-0.5">${icon}</div>
      <div class="flex-1">
        <div class="font-medium">${escapeHtml(ev.message)}</div>
      </div>
    `;

    timelineContainer.appendChild(row);
  }

  lastEventCount = events.length;
  timelineContainer.scrollTop = timelineContainer.scrollHeight;
  fetchAudit();
}

function showApprovalModal(appr) {
  currentPendingApprovalId = appr.id;
  apprTool.textContent = appr.tool;
  apprArgs.textContent = JSON.stringify(appr.args, null, 2);
  apprReason.textContent = appr.reason;
  apprPolicy.textContent = (appr.policy_hits && appr.policy_hits.length > 0)
    ? appr.policy_hits.join(", ")
    : "Data Exfiltration & Alignment Risk";
  if (apprHiddenWrap) {
    if (appr.hidden_instruction) {
      apprHiddenWrap.classList.remove("hidden");
      apprHidden.textContent = appr.hidden_instruction;
    } else {
      apprHiddenWrap.classList.add("hidden");
      apprHidden.textContent = "";
    }
  }
  approvalModal.classList.remove("hidden");
}

function showBreachedOverlay() {
  outcomeOverlay.className = "fixed inset-0 z-50 flex flex-col items-center justify-center p-6 bg-red-950/90 backdrop-blur-xl animate-fade-in";
  outcomeCard.className = "max-w-xl w-full rounded-3xl p-8 border-2 border-red-500 bg-slate-950 shadow-2xl shadow-red-500/30 flex flex-col items-center text-center text-slate-100";
  outcomeIconContainer.className = "w-20 h-20 rounded-full bg-red-600/20 border-2 border-red-500 text-red-500 flex items-center justify-center mb-6 shadow-2xl";
  outcomeIconContainer.innerHTML = `<svg class="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`;

  outcomeHeading.textContent = "BREACHED";
  outcomeHeading.className = "text-5xl font-black tracking-wider uppercase mb-3 text-red-500 animate-pulse";
  outcomeSubtext.textContent = "Prompt injection succeeded. Restricted customer data was silently exfiltrated to an external party.";
  outcomeDetails.className = "w-full p-4 rounded-xl font-mono text-xs text-left mb-6 bg-red-950/40 border border-red-500/40 text-red-200";
  outcomeDetails.innerHTML = `
    <div><strong>Exfiltrated File:</strong> customer_data.csv (250 customer records)</div>
    <div><strong>Canary Token Leaked:</strong> KVC-CANARY-7731</div>
    <div><strong>Recipient:</strong> verify@cloudnest-billing.example (External)</div>
    <div><strong>Root Cause:</strong> Kavach was OFF. Agent read hidden instruction inside Email #3 HTML comment and blindly executed it.</div>
  `;

  dismissOverlayBtn.className = "px-6 py-2.5 rounded-xl font-bold text-sm bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-600/30 transition";
  outcomeOverlay.classList.remove("hidden");
}

function showProtectedOverlay() {
  outcomeOverlay.className = "fixed inset-0 z-50 flex flex-col items-center justify-center p-6 bg-emerald-950/90 backdrop-blur-xl animate-fade-in";
  outcomeCard.className = "max-w-xl w-full rounded-3xl p-8 border-2 border-emerald-500 bg-slate-950 shadow-2xl shadow-emerald-500/30 flex flex-col items-center text-center text-slate-100";
  outcomeIconContainer.className = "w-20 h-20 rounded-full bg-emerald-600/20 border-2 border-emerald-500 text-emerald-400 flex items-center justify-center mb-6 shadow-2xl";
  outcomeIconContainer.innerHTML = `<svg class="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>`;

  outcomeHeading.textContent = "PROTECTED";
  outcomeHeading.className = "text-5xl font-black tracking-wider uppercase mb-3 text-emerald-400";
  outcomeSubtext.textContent = "Attack intercepted and blocked by Kavach. Legitimate user tasks completed successfully.";
  outcomeDetails.className = "w-full p-4 rounded-xl font-mono text-xs text-left mb-6 bg-emerald-950/40 border border-emerald-500/40 text-emerald-200";
  outcomeDetails.innerHTML = `
    <div><strong>Lock 1 (Input Screening):</strong> Email #3 flagged (Hidden instruction detected)</div>
    <div><strong>Lock 2 (Task Alignment Check):</strong> Exfiltration tool call halted (ASK)</div>
    <div><strong>Human Decision:</strong> Blocked by operator</div>
    <div><strong>Legitimate Tasks Executed:</strong></div>
    <div class="ml-3 text-emerald-300">✓ Electricity Bill Paid: Rs 3,420 (Delhi Power Board)</div>
    <div class="ml-3 text-emerald-300">✓ Project Report Sent to Manager Karan Mehta</div>
    <div><strong>Confidential Customer Data:</strong> 100% Safe Inside Organization</div>
  `;

  dismissOverlayBtn.className = "px-6 py-2.5 rounded-xl font-bold text-sm bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-600/30 transition";
  outcomeOverlay.classList.remove("hidden");
}

// Fetch Audit Trail & Verify
async function fetchAudit() {
  try {
    const [auditRes, verifyRes] = await Promise.all([
      fetch("/audit"),
      fetch("/audit/verify")
    ]);

    const entries = await auditRes.json();
    const verification = await verifyRes.json();

    if (verification.ok) {
      auditIntegrityBadge.innerHTML = `
        <svg class="w-3.5 h-3.5 text-emerald-400" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
        <span>Log integrity: verified ✓ (${verification.length} entries)</span>
      `;
      auditIntegrityBadge.className = "px-3 py-1 rounded-full text-xs font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1.5";
    } else {
      auditIntegrityBadge.innerHTML = `<span>⚠️ Tampering Detected at seq #${verification.broken_seq}</span>`;
      auditIntegrityBadge.className = "px-3 py-1 rounded-full text-xs font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/30";
    }

    auditTableBody.innerHTML = "";
    entries.slice().reverse().forEach((entry) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-slate-800/40 transition-colors";

      let resultColor = "text-slate-300";
      if (entry.result === "BLOCKED" || entry.result === "FLAGGED" || entry.result === "BLOCKED_BY_HUMAN") {
        resultColor = "text-red-400 font-bold";
      } else if (entry.result === "ALLOW" || entry.result === "SAFE" || entry.result === "SUCCESS") {
        resultColor = "text-emerald-400 font-semibold";
      } else if (entry.result === "ASK") {
        resultColor = "text-amber-400 font-bold";
      }

      tr.innerHTML = `
        <td class="px-4 py-2 font-bold text-slate-400">#${entry.seq}</td>
        <td class="px-4 py-2 uppercase text-[10px] text-blue-400 font-semibold">${escapeHtml(entry.kind)}</td>
        <td class="px-4 py-2 max-w-xs truncate" title="${escapeHtml(entry.detail)}">${escapeHtml(entry.detail)}</td>
        <td class="px-4 py-2 ${resultColor}">${escapeHtml(entry.result)}</td>
        <td class="px-4 py-2 text-slate-400 max-w-sm truncate" title="${escapeHtml(entry.reason)}">${escapeHtml(entry.reason)}</td>
        <td class="px-4 py-2 text-slate-500 text-[10px]" title="${entry.hash}">${entry.hash ? entry.hash.substring(0, 10) + '...' : '-'}</td>
      `;
      auditTableBody.appendChild(tr);
    });

  } catch (err) {
    console.error("Failed to fetch audit log", err);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

document.addEventListener("DOMContentLoaded", init);

// ---- V4: PII demo, Memory Sentinel, Round 2 ----
async function loadV4() {
  try {
    const r = await fetch("/api/redact-demo");
    const d = await r.json();
    const box = document.getElementById("piiBox");
    if (box) box.textContent = "Masked: " + (d.masked || []).join(", ") + "\n\n" + (d.redacted || "");
  } catch (e) {}
  try {
    const r = await fetch("/api/memory");
    const d = await r.json();
    const el = document.getElementById("memoryBody");
    if (el) el.textContent = d.total + " entries · " + d.clean + " clean · " + d.quarantined +
      " quarantined (memory_poisoned)\n" + (d.entries || []).map(e => (e.quarantined ? "⛔ " : "✅ ") + e.id + " — " + (e.hits || []).join(",")).join("\n");
  } catch (e) {}
}
loadV4();
const _rt2Btn = document.getElementById("redteamRound2Btn");
if (_rt2Btn) _rt2Btn.addEventListener("click", async () => {
  _rt2Btn.disabled = true;
  await fetch("/api/redteam/round2", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({n: 20, source: "library", mutate_all: true})});
  _rt2Btn.disabled = false;
});
function renderRound2(r) {
  const el = document.getElementById("rtRound2");
  if (!el || !r || !r.round2) return;
  const r2 = r.round2;
  el.textContent = "Round 2: mutated " + (r2.mutated || 0) + " · blocked " + (r2.blocked || 0) + "/" + (r2.total || 0) +
    " · ASR " + (r.asr ?? "") + " / FPR " + (r.fpr ?? "") +
    " · Round 2 ASR " + (r2.asr ?? "") + " · regressions saved: " + ((r2.regressions || []).length);
}

// ---- V3: honeypot banner, budget meter, replay, incident, contract ----
async function pollV3() {
  try {
    const st = await (await fetch("/api/state")).json();
    const banner = document.getElementById("honeypotBanner");
    if (banner) banner.classList.toggle("hidden", !st.honeypot_triggered);
    const bm = document.getElementById("budgetMeter");
    if (bm && st.budget) {
      const b = st.budget;
      bm.textContent = `Calls ${b.total_calls||0}/20 · Emails ${b.send_email||0}/5 · Reads ${b.file_reads||0}/10 · Paid Rs ${(b.total_paid||0).toLocaleString("en-IN")} / Rs 10,000` + (st.budget_exceeded ? " — BUDGET EXCEEDED, auto-paused" : "");
    }
    const cl = document.getElementById("contractLine");
    if (cl && st.contract) {
      cl.textContent = `Intent contract ${st.contract.contract_id} · hash ${String(st.contract.hash||"").slice(0,12)}… · expires in 10 min · pay_bill ≤ Rs 10,000 to Delhi Power Board only · send_email to karan.mehta@brightpath.example only`;
    }
    const ib = document.getElementById("incidentBox");
    if (ib && st.incident) {
      ib.textContent = st.incident.summary || st.incident.title || "";
    }
    const rb = document.getElementById("replayBox");
    if (rb && st.status !== "idle" && st.status !== "running") {
      const rep = await (await fetch("/api/replay")).json();
      rb.innerHTML = (rep.steps || []).map(s => `<div>${s.n}. ${s.text}</div>`).join("") || "No steps yet.";
    }
  } catch (e) { /* dashboard stays usable if v3 poll fails */ }
}
setInterval(pollV3, 2000);
const _egressBtn = document.getElementById("egressBtn");
if (_egressBtn) _egressBtn.addEventListener("click", async () => {
  const r = await fetch("/api/egress-test", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({url: "https://evil.example/steal"})});
  const d = await r.json();
  const el = document.getElementById("egressResult");
  if (el) el.textContent = d.result === "blocked" ? "DIRECT = blocked (egress_blocked)" : d.result;
});


// Footer: show which Google AI / Cloud pieces power this instance
(async function showGoogleStack() {
  try {
    const r = await fetch("/api/platform");
    const p = await r.json();
    const el = document.getElementById("googleStack");
    if (!el) return;
    const where = p.deployment === "Local" ? "Running locally" : `Running on ${p.deployment}`;
    const gem = p.gemini === "live" ? `Gemini live (${p.models.screening || "Gemini"})` : "Gemini: offline rules";
    el.textContent = `${where} \u00b7 ${gem} \u00b7 Built with Antigravity \u00b7 Agent Skill: kavach-guard`;
  } catch (e) { /* keep static text */ }
})();
