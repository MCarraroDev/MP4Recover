<?php
declare(strict_types=1);

// Default language
$default_lang = 'en';

// Available languages
$available_langs = ['en', 'it', 'ja'];

// Detect language
$lang = $default_lang;
if (isset($_GET['lang']) && in_array($_GET['lang'], $available_langs)) {
    $lang = $_GET['lang'];
    setcookie('lang', $lang, time() + 60*60*24*30, '/');
} elseif (isset($_COOKIE['lang']) && in_array($_COOKIE['lang'], $available_langs)) {
    $lang = $_COOKIE['lang'];
} elseif (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
    $accept = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
    if (in_array($accept, $available_langs)) {
        $lang = $accept;
    }
}

// Translations
$trans = [
    'en' => [
        'title_index' => 'Easily Recover Broken MP4 Files! - MP4Recover',
        'title_status' => 'Recovery Status - MP4Recover',
        'hero_title' => 'Easily Recover Broken MP4 Files',
        'hero_desc' => 'Recover broken MP4 files using every advanced technical means available (fix_avcC, ffmpeg, MP4Box, remoover, untrunc, reencode, etc.). If this tool cannot recover it, it is likely unrecoverable.',
        'label_broken' => 'Broken MP4 File',
        'label_reference' => '(Optional) Good MP4 File from same device',
        'desc_reference' => 'If provided, the chance of recovery increases (significantly).',
        'btn_upload' => 'Upload and Start Recovery',
        'footer_note' => 'Developed by <a href="https://github.com/MCarraroDev" class="underline decoration-dotted underline-offset-4 hover:decoration-solid text-blue-700 dark:text-blue-300">MCarraroDev</a>. Special thanks to <a href="https://github.com/ActiveTK" class="underline decoration-dotted underline-offset-4 hover:decoration-solid text-blue-700 dark:text-blue-300">ActiveTK</a>.',
        'status_title' => 'Recovery Status',
        'btn_another' => 'Process Another File',
        'internal_id' => 'Internal ID:',
        'status_loading' => 'Loading...',
        'btn_expand' => 'Expand All',
        'btn_collapse' => 'Collapse All',
        'status_success' => 'Recovery Complete.',
        'desc_success' => 'Most of the video was successfully recovered. Please download to check.',
        'btn_download' => 'Download',
        'status_partial' => 'Partial Recovery (0.1s+ or audio only).',
        'desc_partial' => 'Uploading a good video shot in the same environment increases success rate.',
        'btn_download_partial' => 'Download Partial Result',
        'status_failed' => 'Recovery Failed.',
        'desc_failed' => 'All recovery methods failed. If you have another video shot in the same environment, selecting it may increase recovery chances.',
        'state_label' => 'State:',
        'orig_file_label' => 'Original File:',
        'step_start' => 'Start:',
        'step_end' => ' / End:',
        'err_job_required' => 'job is required',
        'err_post_required' => 'Please send via POST.',
        'err_upload_failed' => 'Failed to upload broken MP4 file.',
        'err_mkdir_failed' => 'Failed to create server-side directory.',
        'err_save_failed' => 'Failed to save uploaded file.',
        'err_curl_error' => 'Failed to start recovery (cURL error: %s)',
        'err_http_error' => 'Failed to start recovery (HTTP %s: %s)',
        'err_internal_comm' => 'Failed to communicate with internal server.',
    ],
    'it' => [
        'title_index' => 'Recupera Facilmente File MP4 Corrotti! - MP4Recover',
        'title_status' => 'Stato Recupero - MP4Recover',
        'hero_title' => 'Recupera Facilmente File MP4 Corrotti',
        'hero_desc' => 'Recupera file MP4 corrotti utilizzando ogni mezzo tecnico avanzato disponibile (fix_avcC, ffmpeg, MP4Box, remoover, untrunc, reencode, etc.). Se questo strumento non riesce a recuperarlo, probabilmente è irrecuperabile.',
        'label_broken' => 'File MP4 Corrotto',
        'label_reference' => '(Opzionale) File MP4 Funzionante dallo stesso dispositivo',
        'desc_reference' => 'Se fornito, la probabilità di recupero aumenta (significativamente).',
        'btn_upload' => 'Carica e Avvia Recupero',
        'footer_note' => 'Sviluppato da <a href="https://github.com/MCarraroDev" class="underline decoration-dotted underline-offset-4 hover:decoration-solid text-blue-700 dark:text-blue-300">MCarraroDev</a>. Un ringraziamento speciale a <a href="https://github.com/ActiveTK" class="underline decoration-dotted underline-offset-4 hover:decoration-solid text-blue-700 dark:text-blue-300">ActiveTK</a>.',
        'status_title' => 'Stato Recupero',
        'btn_another' => 'Processa un altro file',
        'internal_id' => 'ID Interno:',
        'status_loading' => 'Caricamento...',
        'btn_expand' => 'Espandi Tutto',
        'btn_collapse' => 'Comprimi Tutto',
        'status_success' => 'Recupero Completato.',
        'desc_success' => 'La maggior parte del video è stata recuperata con successo. Scarica per controllare.',
        'btn_download' => 'Scarica',
        'status_partial' => 'Recupero Parziale (0.1s+ o solo audio).',
        'desc_partial' => 'Caricare un video funzionante girato nello stesso ambiente aumenta il tasso di successo.',
        'btn_download_partial' => 'Scarica Risultato Parziale',
        'status_failed' => 'Recupero Fallito.',
        'desc_failed' => 'Tutti i metodi di recupero sono falliti. Se hai un altro video girato nello stesso ambiente, selezionarlo potrebbe aumentare le probabilità di recupero.',
        'state_label' => 'Stato:',
        'orig_file_label' => 'File Originale:',
        'step_start' => 'Inizio:',
        'step_end' => ' / Fine:',
        'err_job_required' => 'job è richiesto',
        'err_post_required' => 'Si prega di inviare via POST.',
        'err_upload_failed' => 'Caricamento del file MP4 corrotto fallito.',
        'err_mkdir_failed' => 'Creazione della directory lato server fallita.',
        'err_save_failed' => 'Salvataggio del file caricato fallito.',
        'err_curl_error' => 'Avvio del recupero fallito (errore cURL: %s)',
        'err_http_error' => 'Avvio del recupero fallito (HTTP %s: %s)',
        'err_internal_comm' => 'Comunicazione con il server interno fallita.',
    ],
    'ja' => [
        'title_index' => '【完全無料】壊れたMP4ファイルを簡単に復元！ - MP4Recover',
        'title_status' => '復元の進捗状況 - MP4Recover',
        'hero_title' => '壊れたMP4ファイルを簡単に復元できるツール「MP4Recover」',
        'hero_desc' => '壊れたMP4ファイルをありとあらゆる高度な技術的手段(fix_avcC, ffmpeg, MP4Box, remoover, untrunc, reencode, etc.)で復元します。おそらくこのツールで復元できない動画は、どうあがいても復元できません。',
        'label_broken' => '壊れたMP4ファイル',
        'label_reference' => '(任意) 同じ環境で撮影した正常なMP4ファイル',
        'desc_reference' => 'もしあれば、復元できる可能性が(とても)高くなります。',
        'btn_upload' => 'アップロードして復元開始',
        'footer_note' => '開発者: <a href="https://github.com/MCarraroDev" class="underline decoration-dotted underline-offset-4 hover:decoration-solid text-blue-700 dark:text-blue-300">MCarraroDev</a>. 特別な感謝: <a href="https://github.com/ActiveTK" class="underline decoration-dotted underline-offset-4 hover:decoration-solid text-blue-700 dark:text-blue-300">ActiveTK</a>.',
        'status_title' => '復元の進捗状況',
        'btn_another' => '別のファイルを処理',
        'internal_id' => '内部ID:',
        'status_loading' => '読み込み中...',
        'btn_expand' => '全て展開',
        'btn_collapse' => '全て折りたたむ',
        'status_success' => '復元が完了しました。',
        'desc_success' => '大部分の復元に成功しました。ダウンロードしてご確認ください。',
        'btn_download' => 'ダウンロード',
        'status_partial' => '部分的に復元成功（0.1秒以上または音声トラックのみ）。',
        'desc_partial' => '同じ環境で撮影した正常な動画を一緒にアップロードすると成功率が上がります。',
        'btn_download_partial' => '部分結果をダウンロード',
        'status_failed' => '復元に失敗しました。',
        'desc_failed' => '全ての修復方法に失敗しました。もし同じ環境で撮影した別の動画があれば、選択すると復元できる可能性が高くなります。',
        'state_label' => '状態:',
        'orig_file_label' => '元ファイル:',
        'step_start' => '開始:',
        'step_end' => ' / 終了:',
        'err_job_required' => 'job is required',
        'err_post_required' => 'POSTで送信してください。',
        'err_upload_failed' => '壊れたMP4ファイルのアップロードに失敗しました。',
        'err_mkdir_failed' => 'サーバ側保存ディレクトリの作成に失敗しました。',
        'err_save_failed' => 'アップロードの保存に失敗しました。',
        'err_curl_error' => '復元開始に失敗しました（cURL error: %s）',
        'err_http_error' => '復元開始に失敗しました（HTTP %s: %s）',
        'err_internal_comm' => 'サーバー内部の通信に失敗しました。',
    ]
];

function __(string $key, ...$args): string {
    global $trans, $lang;
    $text = $trans[$lang][$key] ?? $trans['en'][$key] ?? $key;
    if (!empty($args)) {
        return sprintf($text, ...$args);
    }
    return $text;
}
