<?php
  declare(strict_types=1);
  define('disable_sanitize_output', 'true');
  require __DIR__ . '/languages.php';
  $job = isset($_GET['job']) ? (string)$_GET['job'] : '';
  if ($job === '') { http_response_code(400); echo __('err_job_required'); exit; }
?>
<!doctype html>
<html lang="<?php echo htmlspecialchars($lang); ?>">
<head>
  <meta charset="utf-8">
  <title><?php echo __('title_status'); ?></title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta name="robots" content="noindex, nofollow">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>tailwind.config={darkMode:"media",theme:{extend:{keyframes:{float:{"0%,100%":{transform:"translateY(0px)"},"50%":{transform:"translateY(-6px)"}},shimmer:{"0%":{transform:"translateX(-100%)"},"100%":{transform:"translateX(100%)"}},pulseGlow:{"0%,100%":{boxShadow:"0 0 0 0 rgba(59,130,246,0.45)"},"50%":{boxShadow:"0 0 36px 6px rgba(59,130,246,0.25)"}}},animation:{float:"float 6s ease-in-out infinite",shimmer:"shimmer 1.75s linear infinite",pulseGlow:"pulseGlow 3s ease-in-out infinite"}}}};</script>
  <style>.bg-mesh{--g1:radial-gradient(35% 25% at 20% 10%,rgba(99,102,241,.35),transparent 60%);--g2:radial-gradient(35% 25% at 85% 20%,rgba(59,130,246,.35),transparent 60%);--g3:radial-gradient(35% 25% at 50% 85%,rgba(16,185,129,.30),transparent 60%);background-image:radial-gradient(90% 60% at 10% -10%,rgba(255,255,255,.12),transparent 70%),radial-gradient(90% 60% at 110% 10%,rgba(255,255,255,.08),transparent 70%),var(--g1),var(--g2),var(--g3);background-blend-mode:screen,screen,normal,normal,normal}.bg-grid{background-image:linear-gradient(to right,rgba(255,255,255,.08) 1px,transparent 1px),linear-gradient(to bottom,rgba(255,255,255,.08) 1px,transparent 1px);background-size:24px 24px;mask-image:radial-gradient(circle at 50% 30%,black 30%,transparent 75%)}.noise{pointer-events:none;position:absolute;inset:0;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='220' height='220' viewBox='0 0 220 220'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3CfeComponentTransfer%3E%3CfeFuncA type='table' tableValues='0 0 0 0 .02 .03 .02 0 0 0 0'/%3E%3C/feComponentTransfer%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.25'/%3E%3C/svg%3E");mix-blend-mode:soft-light;opacity:.6}.glass{background:linear-gradient(to bottom right,rgba(255,255,255,.12),rgba(255,255,255,.06));backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.22)}@media (prefers-color-scheme:light){.glass{background:linear-gradient(to bottom right,rgba(255,255,255,.75),rgba(255,255,255,.55));border:1px solid rgba(15,23,42,.08)}.bg-grid{background-image:linear-gradient(to right,rgba(15,23,42,.06) 1px,transparent 1px),linear-gradient(to bottom,rgba(15,23,42,.06) 1px,transparent 1px)}}details>summary{cursor:pointer;list-style:none}details>summary::-webkit-details-marker{display:none}.caret::before{content:'▶';display:inline-block;transform:rotate(0deg);transition:transform .15s ease;margin-right:.4rem}details[open] .caret::before{transform:rotate(90deg)}pre{white-space:pre-wrap;word-break:break-word}code.inline{background:#f3f4f6;padding:.1rem .3rem;border-radius:.25rem}@media (prefers-color-scheme:dark){pre{background:rgba(255,255,255,.05);border-color:rgba(255,255,255,.15);color:rgba(255,255,255,.9)}code.inline{background:rgba(255,255,255,.08)}}</style>
</head>
<body class="min-h-dvh relative overflow-x-hidden bg-gradient-to-br from-slate-50 to-slate-200 dark:from-slate-950 dark:to-slate-900 text-slate-800 dark:text-slate-100">

  <div class="pointer-events-none absolute -inset-32 bg-mesh opacity-80 dark:opacity-60"></div>
  <div class="pointer-events-none absolute inset-0 bg-grid"></div>
  <div class="noise"></div>

  <div aria-hidden="true" class="pointer-events-none absolute -top-24 -left-24 h-80 w-80 rounded-full bg-blue-500/30 blur-3xl animate-float"></div>
  <div aria-hidden="true" class="pointer-events-none absolute -bottom-24 -right-24 h-96 w-96 rounded-full bg-indigo-500/25 blur-3xl animate-float" style="animation-delay:1.1s"></div>

  <div class="pointer-events-none absolute left-1/2 top-0 h-[2px] w-[120vw] -translate-x-1/2 overflow-hidden">
    <div class="h-full w-1/3 bg-gradient-to-r from-transparent via-white/70 to-transparent dark:via-white/30 animate-shimmer"></div>
  </div>

  <div class="relative max-w-4xl mx-auto py-10 md:py-16 px-4">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-2xl md:text-3xl font-semibold tracking-tight leading-snug bg-clip-text text-transparent bg-gradient-to-r from-slate-800 via-blue-700 to-emerald-600 dark:from-white dark:via-blue-300 dark:to-emerald-300 drop-shadow-sm">
        <?php echo __('status_title'); ?>
      </h1>
      <a href="index.php"
         class="text-sm font-medium text-blue-700 dark:text-blue-300 underline decoration-dotted underline-offset-4 hover:decoration-solid focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded px-2 py-1">
        <?php echo __('btn_another'); ?>
      </a>
    </div>

    <div id="card" class="glass shadow-2xl shadow-blue-500/10 ring-1 ring-black/5 dark:ring-white/10 rounded-2xl p-6 md:p-8 transition-transform duration-300 hover:translate-y-[-2px]">
      <div class="mb-3 text-xs text-slate-600 dark:text-slate-300/80">
        <?php echo __('internal_id'); ?> <code class="inline"><?php echo htmlspecialchars($job, ENT_QUOTES); ?></code>
      </div>

      <div id="summary" class="mb-5 text-sm text-slate-800 dark:text-slate-200/90"><?php echo __('status_loading'); ?></div>

      <div class="flex flex-wrap gap-3 mb-5">
        <button id="expandAll"
                class="relative inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold
                       bg-white/80 dark:bg-white/5 border border-slate-200/80 dark:border-white/10
                       hover:bg-white/95 dark:hover:bg-white/10 shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
          <?php echo __('btn_expand'); ?>
          <span aria-hidden="true" class="absolute inset-0 rounded-lg ring-1 ring-black/5 dark:ring-white/10 pointer-events-none"></span>
        </button>

        <button id="collapseAll"
                class="relative inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold
                       bg-white/80 dark:bg-white/5 border border-slate-200/80 dark:border-white/10
                       hover:bg-white/95 dark:hover:bg-white/10 shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
          <?php echo __('btn_collapse'); ?>
          <span aria-hidden="true" class="absolute inset-0 rounded-lg ring-1 ring-black/5 dark:ring-white/10 pointer-events-none"></span>
        </button>
      </div>

      <div id="steps" class="space-y-2"></div>

      <div id="result_success" class="mt-6 hidden">
        <div class="p-4 md:p-5 bg-green-50/90 dark:bg-emerald-500/10 border border-green-200 dark:border-emerald-400/30 rounded-xl">
          <p class="text-green-800 dark:text-emerald-300 font-medium"><?php echo __('status_success'); ?></p>
          <p class="text-sm text-green-700 dark:text-emerald-200/90 mt-2"><?php echo __('desc_success'); ?></p>
          <div class="mt-3">
            <a id="download_success" href="#"
               class="relative inline-flex items-center justify-center gap-2 rounded-lg px-5 py-3 text-sm font-semibold text-white
                      bg-gradient-to-r from-green-600 via-emerald-600 to-teal-600
                      hover:from-green-500 hover:via-emerald-500 hover:to-teal-500
                      focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-emerald-500 dark:focus-visible:ring-offset-0
                      shadow-lg animate-pulseGlow">
              <?php echo __('btn_download'); ?>
              <span aria-hidden="true" class="pointer-events-none absolute inset-0 rounded-lg ring-1 ring-white/20"></span>
            </a>
          </div>
        </div>
      </div>

      <div id="result_partial" class="mt-6 hidden">
        <div class="p-4 md:p-5 bg-yellow-50/90 dark:bg-yellow-500/10 border border-yellow-200 dark:border-yellow-400/30 rounded-xl">
          <p class="text-yellow-900 dark:text-yellow-200 font-medium"><?php echo __('status_partial'); ?></p>
          <p class="text-sm text-yellow-800 dark:text-yellow-100/90 mt-2"><?php echo __('desc_partial'); ?></p>
          <div class="mt-3">
            <a id="download_partial" href="#"
               class="relative inline-flex items-center justify-center gap-2 rounded-lg px-5 py-3 text-sm font-semibold text-white
                      bg-gradient-to-r from-yellow-600 via-amber-600 to-orange-600
                      hover:from-yellow-500 hover:via-amber-500 hover:to-orange-500
                      focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-amber-500 dark:focus-visible:ring-offset-0
                      shadow-lg">
              <?php echo __('btn_download_partial'); ?>
              <span aria-hidden="true" class="pointer-events-none absolute inset-0 rounded-lg ring-1 ring-white/20"></span>
            </a>
          </div>
        </div>
      </div>

      <div id="failed" class="mt-6 hidden">
        <div class="p-4 md:p-5 bg-red-50/90 dark:bg-red-500/10 border border-red-200 dark:border-red-400/30 rounded-xl">
          <p class="text-red-800 dark:text-red-300 font-medium" id="failTitle"><?php echo __('status_failed'); ?></p>
          <p class="text-sm text-red-700 dark:text-red-200/90 mt-2" id="failNote"><?php echo __('desc_failed'); ?></p>
        </div>
      </div>
    </div>
  </div>

<script>
window.currentFN="";const job = <?php echo json_encode($job); ?>;
const LANG = {
    state: "<?php echo __('state_label'); ?>",
    orig: "<?php echo __('orig_file_label'); ?>",
    start: "<?php echo __('step_start'); ?>",
    end: "<?php echo __('step_end'); ?>"
};
let timer=null;function stopPoll(){timer&&(clearInterval(timer),timer=null)}function stripAnsi(e){return e?(e=e.replace(/\x1B\[[0-?]*[ -/]*[@-~]/g,"")).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g,""):""}function esc(e){return String(e??"").replace(/[&<>"']/g,e=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[e])}function badge(e){switch(e){case"queued":return"bg-gray-600 dark:bg-gray-500";case"running":return"bg-blue-600";case"success":return"bg-green-600";case"part_success":return"bg-yellow-600";case"failed":return"bg-red-600";default:return"bg-gray-600"}}async function fetchStatus(){try{var e=await(await fetch("status-proxy.php?"+new URLSearchParams({job:job}))).json();e._error?(document.getElementById("summary").textContent="Error: "+e._error,stopPoll()):render(e)}catch(e){document.getElementById("summary").textContent="Fetch Error: "+e.message,stopPoll()}}function render(e){var t=document.getElementById("summary");const n=document.getElementById("steps");var s=document.getElementById("result_success"),a=document.getElementById("result_partial"),d=document.getElementById("failed");window.currentFN=e.orig_filename;t.innerHTML=`
    <div class="flex items-center gap-2 flex-wrap">
      <span class="text-slate-600 dark:text-slate-300/90">${LANG.state}</span>
      <span class="px-2 py-0.5 rounded text-white ${badge(e.status)}">${esc(e.status)}</span>
      ${e.orig_filename?`<span class="text-slate-500 dark:text-slate-400 ml-2">${LANG.orig}</span><code class="inline">${esc(e.orig_filename)}</code>`:""}
    </div>`,n.innerHTML="",(e.steps||[]).forEach(e=>{var t=stripAnsi(e.message||""),s=document.createElement("details"),a=(s.className="rounded-xl border border-slate-200/80 dark:border-white/10 overflow-hidden bg-white/70 dark:bg-white/5 shadow-sm",`
      <summary class="select-none px-3 md:px-4 py-2.5 flex items-center justify-between hover:bg-slate-50/80 dark:hover:bg-white/10 transition-colors">
        <div class="flex items-center gap-2">
          <span class="caret"></span>
          <span class="font-medium text-slate-800 dark:text-slate-100">${esc(e.name)}</span>
<?php
  declare(strict_types=1);
  define('disable_sanitize_output', 'true');
  require __DIR__ . '/languages.php';
  $job = isset($_GET['job']) ? (string)$_GET['job'] : '';
  if ($job === '') { http_response_code(400); echo __('err_job_required'); exit; }
?>
<!doctype html>
<html lang="<?php echo htmlspecialchars($lang); ?>">
<head>
  <meta charset="utf-8">
  <title><?php echo __('title_status'); ?></title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta name="robots" content="noindex, nofollow">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>tailwind.config={darkMode:"media",theme:{extend:{keyframes:{float:{"0%,100%":{transform:"translateY(0px)"},"50%":{transform:"translateY(-6px)"}},shimmer:{"0%":{transform:"translateX(-100%)"},"100%":{transform:"translateX(100%)"}},pulseGlow:{"0%,100%":{boxShadow:"0 0 0 0 rgba(59,130,246,0.45)"},"50%":{boxShadow:"0 0 36px 6px rgba(59,130,246,0.25)"}}},animation:{float:"float 6s ease-in-out infinite",shimmer:"shimmer 1.75s linear infinite",pulseGlow:"pulseGlow 3s ease-in-out infinite"}}}};</script>
  <style>.bg-mesh{--g1:radial-gradient(35% 25% at 20% 10%,rgba(99,102,241,.35),transparent 60%);--g2:radial-gradient(35% 25% at 85% 20%,rgba(59,130,246,.35),transparent 60%);--g3:radial-gradient(35% 25% at 50% 85%,rgba(16,185,129,.30),transparent 60%);background-image:radial-gradient(90% 60% at 10% -10%,rgba(255,255,255,.12),transparent 70%),radial-gradient(90% 60% at 110% 10%,rgba(255,255,255,.08),transparent 70%),var(--g1),var(--g2),var(--g3);background-blend-mode:screen,screen,normal,normal,normal}.bg-grid{background-image:linear-gradient(to right,rgba(255,255,255,.08) 1px,transparent 1px),linear-gradient(to bottom,rgba(255,255,255,.08) 1px,transparent 1px);background-size:24px 24px;mask-image:radial-gradient(circle at 50% 30%,black 30%,transparent 75%)}.noise{pointer-events:none;position:absolute;inset:0;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='220' height='220' viewBox='0 0 220 220'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3CfeComponentTransfer%3E%3CfeFuncA type='table' tableValues='0 0 0 0 .02 .03 .02 0 0 0 0'/%3E%3C/feComponentTransfer%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.25'/%3E%3C/svg%3E");mix-blend-mode:soft-light;opacity:.6}.glass{background:linear-gradient(to bottom right,rgba(255,255,255,.12),rgba(255,255,255,.06));backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.22)}@media (prefers-color-scheme:light){.glass{background:linear-gradient(to bottom right,rgba(255,255,255,.75),rgba(255,255,255,.55));border:1px solid rgba(15,23,42,.08)}.bg-grid{background-image:linear-gradient(to right,rgba(15,23,42,.06) 1px,transparent 1px),linear-gradient(to bottom,rgba(15,23,42,.06) 1px,transparent 1px)}}details>summary{cursor:pointer;list-style:none}details>summary::-webkit-details-marker{display:none}.caret::before{content:'▶';display:inline-block;transform:rotate(0deg);transition:transform .15s ease;margin-right:.4rem}details[open] .caret::before{transform:rotate(90deg)}pre{white-space:pre-wrap;word-break:break-word}code.inline{background:#f3f4f6;padding:.1rem .3rem;border-radius:.25rem}@media (prefers-color-scheme:dark){pre{background:rgba(255,255,255,.05);border-color:rgba(255,255,255,.15);color:rgba(255,255,255,.9)}code.inline{background:rgba(255,255,255,.08)}}</style>
</head>
<body class="min-h-dvh relative overflow-x-hidden bg-gradient-to-br from-slate-50 to-slate-200 dark:from-slate-950 dark:to-slate-900 text-slate-800 dark:text-slate-100">

  <div class="pointer-events-none absolute -inset-32 bg-mesh opacity-80 dark:opacity-60"></div>
  <div class="pointer-events-none absolute inset-0 bg-grid"></div>
  <div class="noise"></div>

  <div aria-hidden="true" class="pointer-events-none absolute -top-24 -left-24 h-80 w-80 rounded-full bg-blue-500/30 blur-3xl animate-float"></div>
  <div aria-hidden="true" class="pointer-events-none absolute -bottom-24 -right-24 h-96 w-96 rounded-full bg-indigo-500/25 blur-3xl animate-float" style="animation-delay:1.1s"></div>

  <div class="pointer-events-none absolute left-1/2 top-0 h-[2px] w-[120vw] -translate-x-1/2 overflow-hidden">
    <div class="h-full w-1/3 bg-gradient-to-r from-transparent via-white/70 to-transparent dark:via-white/30 animate-shimmer"></div>
  </div>

  <div class="relative max-w-4xl mx-auto py-10 md:py-16 px-4">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-2xl md:text-3xl font-semibold tracking-tight leading-snug bg-clip-text text-transparent bg-gradient-to-r from-slate-800 via-blue-700 to-emerald-600 dark:from-white dark:via-blue-300 dark:to-emerald-300 drop-shadow-sm">
        <?php echo __('status_title'); ?>
      </h1>
      <a href="index.php"
         class="text-sm font-medium text-blue-700 dark:text-blue-300 underline decoration-dotted underline-offset-4 hover:decoration-solid focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded px-2 py-1">
        <?php echo __('btn_another'); ?>
      </a>
    </div>

    <div id="card" class="glass shadow-2xl shadow-blue-500/10 ring-1 ring-black/5 dark:ring-white/10 rounded-2xl p-6 md:p-8 transition-transform duration-300 hover:translate-y-[-2px]">
      <div class="mb-3 text-xs text-slate-600 dark:text-slate-300/80">
        <?php echo __('internal_id'); ?> <code class="inline"><?php echo htmlspecialchars($job, ENT_QUOTES); ?></code>
      </div>

      <div id="summary" class="mb-5 text-sm text-slate-800 dark:text-slate-200/90"><?php echo __('status_loading'); ?></div>

      <div class="flex flex-wrap gap-3 mb-5">
        <button id="expandAll"
                class="relative inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold
                       bg-white/80 dark:bg-white/5 border border-slate-200/80 dark:border-white/10
                       hover:bg-white/95 dark:hover:bg-white/10 shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
          <?php echo __('btn_expand'); ?>
          <span aria-hidden="true" class="absolute inset-0 rounded-lg ring-1 ring-black/5 dark:ring-white/10 pointer-events-none"></span>
        </button>

        <button id="collapseAll"
                class="relative inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold
                       bg-white/80 dark:bg-white/5 border border-slate-200/80 dark:border-white/10
                       hover:bg-white/95 dark:hover:bg-white/10 shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
          <?php echo __('btn_collapse'); ?>
          <span aria-hidden="true" class="absolute inset-0 rounded-lg ring-1 ring-black/5 dark:ring-white/10 pointer-events-none"></span>
        </button>
      </div>

      <div id="steps" class="space-y-2"></div>

      <div id="result_success" class="mt-6 hidden">
        <div class="p-4 md:p-5 bg-green-50/90 dark:bg-emerald-500/10 border border-green-200 dark:border-emerald-400/30 rounded-xl">
          <p class="text-green-800 dark:text-emerald-300 font-medium"><?php echo __('status_success'); ?></p>
          <p class="text-sm text-green-700 dark:text-emerald-200/90 mt-2"><?php echo __('desc_success'); ?></p>
          <div class="mt-3">
            <a id="download_success" href="#"
               class="relative inline-flex items-center justify-center gap-2 rounded-lg px-5 py-3 text-sm font-semibold text-white
                      bg-gradient-to-r from-green-600 via-emerald-600 to-teal-600
                      hover:from-green-500 hover:via-emerald-500 hover:to-teal-500
                      focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-emerald-500 dark:focus-visible:ring-offset-0
                      shadow-lg animate-pulseGlow">
              <?php echo __('btn_download'); ?>
              <span aria-hidden="true" class="pointer-events-none absolute inset-0 rounded-lg ring-1 ring-white/20"></span>
            </a>
          </div>
        </div>
      </div>

      <div id="result_partial" class="mt-6 hidden">
        <div class="p-4 md:p-5 bg-yellow-50/90 dark:bg-yellow-500/10 border border-yellow-200 dark:border-yellow-400/30 rounded-xl">
          <p class="text-yellow-900 dark:text-yellow-200 font-medium"><?php echo __('status_partial'); ?></p>
          <p class="text-sm text-yellow-800 dark:text-yellow-100/90 mt-2"><?php echo __('desc_partial'); ?></p>
          <div class="mt-3">
            <a id="download_partial" href="#"
               class="relative inline-flex items-center justify-center gap-2 rounded-lg px-5 py-3 text-sm font-semibold text-white
                      bg-gradient-to-r from-yellow-600 via-amber-600 to-orange-600
                      hover:from-yellow-500 hover:via-amber-500 hover:to-orange-500
                      focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-amber-500 dark:focus-visible:ring-offset-0
                      shadow-lg">
              <?php echo __('btn_download_partial'); ?>
              <span aria-hidden="true" class="pointer-events-none absolute inset-0 rounded-lg ring-1 ring-white/20"></span>
            </a>
          </div>
        </div>
      </div>

      <div id="failed" class="mt-6 hidden">
        <div class="p-4 md:p-5 bg-red-50/90 dark:bg-red-500/10 border border-red-200 dark:border-red-400/30 rounded-xl">
          <p class="text-red-800 dark:text-red-300 font-medium" id="failTitle"><?php echo __('status_failed'); ?></p>
          <p class="text-sm text-red-700 dark:text-red-200/90 mt-2" id="failNote"><?php echo __('desc_failed'); ?></p>
        </div>
      </div>
    </div>
  </div>

<script>
window.currentFN="";const job = <?php echo json_encode($job); ?>;
const LANG = {
    state: "<?php echo __('state_label'); ?>",
    orig: "<?php echo __('orig_file_label'); ?>",
    start: "<?php echo __('step_start'); ?>",
    end: "<?php echo __('step_end'); ?>"
};
let timer=null;function stopPoll(){timer&&(clearInterval(timer),timer=null)}function stripAnsi(e){return e?(e=e.replace(/\x1B\[[0-?]*[ -/]*[@-~]/g,"")).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g,""):""}function esc(e){return String(e??"").replace(/[&<>"']/g,e=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[e])}function badge(e){switch(e){case"queued":return"bg-gray-600 dark:bg-gray-500";case"running":return"bg-blue-600";case"success":return"bg-green-600";case"part_success":return"bg-yellow-600";case"failed":return"bg-red-600";default:return"bg-gray-600"}}async function fetchStatus(){try{var e=await(await fetch("status-proxy.php?"+new URLSearchParams({job:job}))).json();e._error?(document.getElementById("summary").textContent="Error: "+e._error,stopPoll()):render(e)}catch(e){document.getElementById("summary").textContent="Fetch Error: "+e.message,stopPoll()}}function render(e){var t=document.getElementById("summary");const n=document.getElementById("steps");var s=document.getElementById("result_success"),a=document.getElementById("result_partial"),d=document.getElementById("failed");window.currentFN=e.orig_filename;t.innerHTML=`
    <div class="flex items-center gap-2 flex-wrap">
      <span class="text-slate-600 dark:text-slate-300/90">${LANG.state}</span>
      <span class="px-2 py-0.5 rounded text-white ${badge(e.status)}">${esc(e.status)}</span>
      ${e.orig_filename?`<span class="text-slate-500 dark:text-slate-400 ml-2">${LANG.orig}</span><code class="inline">${esc(e.orig_filename)}</code>`:""}
    </div>`,n.innerHTML="",(e.steps||[]).forEach(e=>{var t=stripAnsi(e.message||""),s=document.createElement("details"),a=(s.className="rounded-xl border border-slate-200/80 dark:border-white/10 overflow-hidden bg-white/70 dark:bg-white/5 shadow-sm",`
      <summary class="select-none px-3 md:px-4 py-2.5 flex items-center justify-between hover:bg-slate-50/80 dark:hover:bg-white/10 transition-colors">
        <div class="flex items-center gap-2">
          <span class="caret"></span>
          <span class="font-medium text-slate-800 dark:text-slate-100">${esc(e.name)}</span>
        </div>
        <span class="px-2 py-0.5 rounded text-white text-xs ${badge(e.status)}">${esc(e.status)}</span>
      </summary>`),e=`
      <div class="px-3 md:px-4 pb-3 md:pb-4">
        <div class="text-xs text-slate-600 dark:text-slate-300/80">${e.started_at?LANG.start+" "+esc(e.started_at):""} ${e.finished_at?LANG.end+" "+esc(e.finished_at):""}</div>
        ${t?`<pre class="mt-2 text-sm text-slate-800 dark:text-slate-100 bg-slate-50/80 dark:bg-white/5 border border-slate-200/80 dark:border-white/10 rounded-lg p-3">${esc(t)}</pre>`:""}
      </div>`;s.innerHTML=a+e,n.appendChild(s)}),s.classList.add("hidden"),a.classList.add("hidden"),d.classList.add("hidden"),"success"===e.status?(stopPoll(),s.classList.remove("hidden"),document.getElementById("download_success").href="download.php?job="+encodeURIComponent(e.job_id)):"part_success"===e.status?(stopPoll(),a.classList.remove("hidden"),document.getElementById("download_partial").href="download.php?job="+encodeURIComponent(e.job_id)+"&filename="+encodeURIComponent(window.currentFN)):"failed"===e.status&&(stopPoll(),d.classList.remove("hidden"),document.getElementById("failNote").textContent=e.fail_reason||document.getElementById("failNote").textContent)}document.getElementById("expandAll").addEventListener("click",()=>{document.querySelectorAll("#steps details").forEach(e=>e.open=!0)}),document.getElementById("collapseAll").addEventListener("click",()=>{document.querySelectorAll("#steps details").forEach(e=>e.open=!1)}),fetchStatus(),timer=setInterval(fetchStatus, 1000); // Update every 1 second
</script>
</body>
</html>
