<?php
  declare(strict_types=1);
  require __DIR__ . '/config.php';
  require __DIR__ . '/languages.php';
?>
<!doctype html>
<html lang="<?php echo htmlspecialchars($lang); ?>">
<head>
  <meta charset="utf-8">
  <title><?php echo __('title_index'); ?></title>
  <meta name="robots" content="all">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>tailwind.config={darkMode:"media",theme:{extend:{keyframes:{float:{"0%, 100%":{transform:"translateY(0px)"},"50%":{transform:"translateY(-6px)"}},pulseGlow:{"0%,100%":{boxShadow:"0 0 0 0 rgba(59,130,246,0.45)"},"50%":{boxShadow:"0 0 36px 6px rgba(59,130,246,0.25)"}},shimmer:{"0%":{transform:"translateX(-100%)"},"100%":{transform:"translateX(100%)"}}},animation:{float:"float 6s ease-in-out infinite",pulseGlow:"pulseGlow 3s ease-in-out infinite",shimmer:"shimmer 1.75s linear infinite"}}}};</script>
  <style>.bg-mesh{--g1:radial-gradient(35% 25% at 20% 10%,rgba(99,102,241,.35),transparent 60%);--g2:radial-gradient(35% 25% at 85% 20%,rgba(59,130,246,.35),transparent 60%);--g3:radial-gradient(35% 25% at 50% 85%,rgba(16,185,129,.30),transparent 60%);background-image:radial-gradient(90% 60% at 10% -10%,rgba(255,255,255,.12),transparent 70%),radial-gradient(90% 60% at 110% 10%,rgba(255,255,255,.08),transparent 70%),var(--g1),var(--g2),var(--g3);background-blend-mode:screen,screen,normal,normal,normal}.bg-grid{background-image:linear-gradient(to right,rgba(255,255,255,.08) 1px,transparent 1px),linear-gradient(to bottom,rgba(255,255,255,.08) 1px,transparent 1px);background-size:24px 24px;mask-image:radial-gradient(circle at 50% 30%,black 30%,transparent 75%)}.noise{pointer-events:none;position:absolute;inset:0;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='220' height='220' viewBox='0 0 220 220'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3CfeComponentTransfer%3E%3CfeFuncA type='table' tableValues='0 0 0 0 .02 .03 .02 0 0 0 0'/%3E%3C/feComponentTransfer%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.25'/%3E%3C/svg%3E");mix-blend-mode:soft-light;opacity:.6}.glass{background:linear-gradient(to bottom right,rgba(255,255,255,.12),rgba(255,255,255,.06));backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.22)}@media (prefers-color-scheme:light){.glass{background:linear-gradient(to bottom right,rgba(255,255,255,.75),rgba(255,255,255,.55));border:1px solid rgba(15,23,42,.08)}.bg-grid{background-image:linear-gradient(to right,rgba(15,23,42,.06) 1px,transparent 1px),linear-gradient(to bottom,rgba(15,23,42,.06) 1px,transparent 1px)}}input[type="file"]{@apply block w-full text-sm rounded border border-gray-300/70 dark:border-white/10 focus:outline-none focus:ring-2 focus:ring-blue-500/60 file:mr-4 file:rounded file:border-0 file:px-4 file:py-2 file:cursor-pointer file:bg-blue-600 file:text-white hover:file:bg-blue-700 dark:file:bg-blue-500 dark:hover:file:bg-blue-600}</style>
</head>
<body class="min-h-screen relative overflow-x-hidden bg-gradient-to-br from-slate-50 to-slate-200 dark:from-slate-950 dark:to-slate-900 text-slate-800 dark:text-slate-100">

  <div class="pointer-events-none fixed inset-0 overflow-hidden">
    <div class="absolute -inset-32 bg-mesh opacity-80 dark:opacity-60"></div>
    <div class="absolute inset-0 bg-grid"></div>
    <div class="noise"></div>
    <div aria-hidden="true" class="pointer-events-none absolute -top-24 -left-24 h-80 w-80 rounded-full bg-blue-500/30 blur-3xl animate-float"></div>
    <div aria-hidden="true" class="pointer-events-none absolute -bottom-24 -right-24 h-96 w-96 rounded-full bg-indigo-500/25 blur-3xl animate-float" style="animation-delay:1.2s"></div>
    <div class="absolute left-1/2 top-0 h-[2px] w-screen -translate-x-1/2 overflow-hidden">
      <div class="h-full w-1/3 bg-gradient-to-r from-transparent via-white/70 to-transparent dark:via-white/30 animate-shimmer"></div>
    </div>
  </div>
  <div class="relative mx-auto max-w-3xl px-4 py-14 md:py-24">
    <div class="glass rounded-2xl p-6 md:p-10 shadow-2xl shadow-blue-500/10 ring-1 ring-black/5 dark:ring-white/10 transition-transform duration-300 hover:translate-y-[-2px]">

      <div class="mb-6 md:mb-8">
        <div class="flex justify-between items-start">
            <h1 class="text-2xl md:text-3xl font-semibold tracking-tight leading-snug bg-clip-text text-transparent bg-gradient-to-r from-slate-800 via-blue-700 to-emerald-600 dark:from-white dark:via-blue-300 dark:to-emerald-300 drop-shadow-sm mb-3">
            <?php echo __('hero_title'); ?>
            </h1>
            <div class="flex gap-2 text-sm font-medium">
                <a href="?lang=en" class="<?php echo $lang === 'en' ? 'text-blue-600 dark:text-blue-400' : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'; ?>">EN</a>
                <span class="text-slate-300 dark:text-slate-600">|</span>
                <a href="?lang=it" class="<?php echo $lang === 'it' ? 'text-blue-600 dark:text-blue-400' : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'; ?>">IT</a>
                <span class="text-slate-300 dark:text-slate-600">|</span>
                <a href="?lang=ja" class="<?php echo $lang === 'ja' ? 'text-blue-600 dark:text-blue-400' : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'; ?>">JP</a>
            </div>
        </div>
        <div class="h-px w-full bg-gradient-to-r from-transparent via-slate-300/70 to-transparent dark:via-white/20"></div>
      </div>

      <p class="text-[15px] leading-7 text-slate-700 dark:text-slate-200/90 mb-6">
        <?php echo __('hero_desc'); ?>
      </p>

      <form id="form" class="rounded-xl border border-slate-200/80 dark:border-white/10 bg-white/80 dark:bg-white/5 p-5 md:p-7 shadow-xl shadow-slate-900/5 backdrop-blur"
            action="upload.php" method="post" enctype="multipart/form-data">
        <div class="mb-5">
          <label class="flex items-center gap-2 text-sm font-medium text-slate-800 dark:text-slate-100 mb-2">
            <svg aria-hidden="true" viewBox="0 0 24 24" class="h-5 w-5 text-blue-600 dark:text-blue-400">
              <path fill="currentColor" d="M12 3a5 5 0 0 0-5 5v2H6a4 4 0 0 0 0 8h12a4 4 0 0 0 0-8h-1V8a5 5 0 0 0-5-5Zm-3 7V8a3 3 0 1 1 6 0v2h2a2 2 0 1 1 0 4H7a2 2 0 1 1 0-4h2Z"/>
            </svg>
            </svg>
            <?php echo __('label_broken'); ?>
          </label>
          <input type="file" name="broken" accept="video/mp4" required class="">
        </div>

        <div class="mb-4">
          <label class="flex items-center gap-2 text-sm font-medium text-slate-800 dark:text-slate-100 mb-2">
            <svg aria-hidden="true" viewBox="0 0 24 24" class="h-5 w-5 text-emerald-600 dark:text-emerald-400">
              <path fill="currentColor" d="M4 5h16a1 1 0 0 1 1 1v10.5a1 1 0 0 1-1.447.894L12 14.118l-7.553 3.276A1 1 0 0 1 3 16.5V6a1 1 0 0 1 1-1Z"/>
            </svg>
            </svg>
            <?php echo __('label_reference'); ?>
          </label>
          <input type="file" name="reference" accept="video/mp4" class="">
          <p class="text-xs text-slate-600 dark:text-slate-300/80 mt-2"><?php echo __('desc_reference'); ?></p>
        </div>

        <div class="flex flex-wrap gap-3 pt-2">
          <button type="submit"
                  class="relative inline-flex items-center justify-center gap-2 rounded-lg px-5 py-3 text-sm font-semibold text-white
                         bg-gradient-to-r from-blue-600 via-indigo-600 to-emerald-600
                         hover:from-blue-500 hover:via-indigo-500 hover:to-emerald-500
                         focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-blue-500
                         dark:focus-visible:ring-offset-0 transition-all duration-200
                         shadow-lg animate-pulseGlow">
            <svg aria-hidden="true" viewBox="0 0 24 24" class="h-5 w-5">
              <path fill="currentColor" d="M5 12h6V5l8 7-8 7v-7H5z"/>
            </svg>
            </svg>
            <?php echo __('btn_upload'); ?>
            <span aria-hidden="true" class="pointer-events-none absolute inset-0 rounded-lg ring-1 ring-white/20"></span>
          </button>
        </div>
      </form>

      <p class="mt-6 text-[13px] leading-6 text-slate-600 dark:text-slate-300/80">
        <?php echo __('footer_note'); ?>
      </p>
    </div>
  </div>

  <script>!function(){const t=document.getElementById("form");if(t){const n=t.querySelectorAll('input[type="file"]');["dragenter","dragover"].forEach(e=>t.addEventListener(e,e=>{e.preventDefault(),t.classList.add("ring-2","ring-blue-500/40")})),["dragleave","drop"].forEach(e=>t.addEventListener(e,e=>{e.preventDefault(),t.classList.remove("ring-2","ring-blue-500/40")})),t.addEventListener("drop",e=>{var r,e=e.dataTransfer;e&&e.files&&0!==e.files.length&&(r=t.querySelector('input[name="broken"]')||n[0])&&(r.files=e.files)},!1)}}();</script>
</body>
</html>
