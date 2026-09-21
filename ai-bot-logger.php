<?php
/**
 * Plugin Name: AI Bot Logger
 * Description: Zaznamenáva návštevy AI crawlerov (GPTBot, ClaudeBot, Googlebot, ...) do mesačných súborov v Apache combined formáte.
 * Version: 1.0
 * Author: cervenazelena.sk
 *
 * INŠTALÁCIA: nahrať do wp-content/mu-plugins/ai-bot-logger.php
 * (adresár mu-plugins vytvoriť, ak neexistuje — plugin sa aktivuje sám, netreba ho zapínať)
 *
 * Výstup: wp-content/ai-bot-log/ai-bots-RRRR-MM.log
 * Formát je zhodný s Apache combined, takže ho spracuje rovnaký analyzátor ako serverové logy.
 */

if (!defined('ABSPATH')) { exit; }

const AIBL_DIR = WP_CONTENT_DIR . '/ai-bot-log';

/** Vzory user-agentov, ktoré nás zaujímajú. Poradie nehrá rolu, hľadá sa prvá zhoda. */
function aibl_vzor() {
    return '/(GPTBot|OAI-SearchBot|ChatGPT-User|ClaudeBot|Claude-SearchBot|Claude-User|anthropic-ai|Claude-Web'
         . '|Google-Extended|Google-CloudVertexBot|GoogleOther|Googlebot|Google-InspectionTool'
         . '|CCBot|PerplexityBot|Perplexity-User|Bytespider|TikTokSpider|Amazonbot|Applebot-Extended|Applebot'
         . '|meta-externalagent|Meta-ExternalFetcher|FacebookBot|cohere-ai|cohere-training-data-crawler'
         . '|MistralAI-User|DuckAssistBot|AI2Bot|Diffbot|ImagesiftBot|Omgili|YouBot|Timpibot|Bingbot)/i';
}

/**
 * Skutočná IP klienta — Websupport beží za openresty proxy.
 * X-Real-IP nastavuje proxy a prepisuje ho, preto má prednosť.
 * X-Forwarded-For si vie klient podvrhnúť sám, berieme ho až ako druhý v poradí.
 * Pri overovaní pravosti bota je preto rozhodujúce až porovnanie s oficiálnymi IP rozsahmi.
 */
function aibl_ip() {
    foreach (['HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $k) {
        if (empty($_SERVER[$k])) { continue; }
        // X-Forwarded-For môže byť zoznam, prvá položka je pôvodný klient
        $ip = trim(explode(',', $_SERVER[$k])[0]);
        if (filter_var($ip, FILTER_VALIDATE_IP)) { return $ip; }
    }
    return '-';
}

/** Zaistí, že adresár existuje a nie je verejne čitateľný. */
function aibl_priprav_adresar() {
    if (!is_dir(AIBL_DIR)) {
        if (!wp_mkdir_p(AIBL_DIR)) { return false; }
    }
    $ht = AIBL_DIR . '/.htaccess';
    if (!file_exists($ht)) {
        file_put_contents($ht, "Require all denied\n<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n");
    }
    if (!file_exists(AIBL_DIR . '/index.php')) {
        file_put_contents(AIBL_DIR . '/index.php', "<?php // ticho\n");
    }
    return true;
}

/**
 * Zápis prebieha až na shutdown, aby sme poznali HTTP status a nezdržiavali odpoveď.
 */
function aibl_zapis() {
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if ($ua === '' || !preg_match(aibl_vzor(), $ua)) { return; }
    if (!aibl_priprav_adresar()) { return; }

    $riadok = sprintf(
        '%s - - [%s] "%s %s %s" %d %s "%s" "%s"' . "\n",
        aibl_ip(),
        gmdate('d/M/Y:H:i:s') . ' +0000',
        str_replace('"', '', $_SERVER['REQUEST_METHOD'] ?? 'GET'),
        str_replace('"', '', $_SERVER['REQUEST_URI'] ?? '/'),
        str_replace('"', '', $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1'),
        function_exists('http_response_code') ? (http_response_code() ?: 200) : 200,
        '-',
        str_replace('"', '', $_SERVER['HTTP_REFERER'] ?? '-'),
        str_replace('"', '', $ua)
    );

    $subor = AIBL_DIR . '/ai-bots-' . gmdate('Y-m') . '.log';
    // LOCK_EX zabráni prepleteniu riadkov pri súbežných požiadavkách
    @file_put_contents($subor, $riadok, FILE_APPEND | LOCK_EX);
}
add_action('shutdown', 'aibl_zapis', 999);
