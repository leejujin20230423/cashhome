<?php

declare(strict_types=1);

/**
 * admin_login_log_common.php
 * - 관리자 로그인 로그(위치/기기/IP) 저장 공통 함수
 * - 테이블이 없거나 외부 위치 조회 실패 시 로그인 본 기능은 계속 진행
 */

if (!function_exists('cashhome_admin_loginlog_is_valid_ip')) {
    function cashhome_admin_loginlog_is_valid_ip(string $ip): bool
    {
        if ($ip === '' || strlen($ip) > 64) {
            return false;
        }

        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
}

if (!function_exists('cashhome_admin_loginlog_pick_ip')) {
    function cashhome_admin_loginlog_pick_ip(): string
    {
        $candidates = [];

        $cfIp = trim((string)($_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''));
        if ($cfIp !== '') {
            $candidates[] = $cfIp;
        }

        $realIp = trim((string)($_SERVER['HTTP_X_REAL_IP'] ?? ''));
        if ($realIp !== '') {
            $candidates[] = $realIp;
        }

        $xff = trim((string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
        if ($xff !== '') {
            $parts = explode(',', $xff);
            foreach ($parts as $part) {
                $part = trim((string)$part);
                if ($part !== '') {
                    $candidates[] = $part;
                }
            }
        }

        $remoteAddr = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
        if ($remoteAddr !== '') {
            $candidates[] = $remoteAddr;
        }

        foreach ($candidates as $candidate) {
            if (cashhome_admin_loginlog_is_valid_ip($candidate)) {
                return $candidate;
            }
        }

        return '';
    }
}

if (!function_exists('cashhome_admin_loginlog_detect_device_type')) {
    function cashhome_admin_loginlog_detect_device_type(): string
    {
        $ua = strtolower((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
        if ($ua === '') {
            return 'unknown';
        }

        $isTablet = (strpos($ua, 'ipad') !== false)
            || (strpos($ua, 'tablet') !== false)
            || (strpos($ua, 'android') !== false && strpos($ua, 'mobile') === false);

        if ($isTablet) {
            return 'tablet';
        }

        $isMobile = (strpos($ua, 'mobi') !== false)
            || (strpos($ua, 'mobile') !== false)
            || (strpos($ua, 'iphone') !== false)
            || (strpos($ua, 'ipod') !== false)
            || (strpos($ua, 'android') !== false && strpos($ua, 'mobile') !== false);

        if ($isMobile) {
            return 'mobile';
        }

        return 'web';
    }
}

if (!function_exists('cashhome_admin_loginlog_detect_browser')) {
    function cashhome_admin_loginlog_detect_browser(string $ua): string
    {
        $uaLower = strtolower($ua);
        if ($uaLower === '') {
            return '';
        }

        $map = [
            'edg/' => 'Edge',
            'opr/' => 'Opera',
            'opera/' => 'Opera',
            'chrome/' => 'Chrome',
            'safari/' => 'Safari',
            'firefox/' => 'Firefox',
            'trident/' => 'IE',
            'msie ' => 'IE',
        ];

        foreach ($map as $needle => $label) {
            if (strpos($uaLower, $needle) !== false) {
                return $label;
            }
        }

        return 'Unknown';
    }
}

if (!function_exists('cashhome_admin_loginlog_detect_os')) {
    function cashhome_admin_loginlog_detect_os(string $ua): string
    {
        $uaLower = strtolower($ua);
        if ($uaLower === '') {
            return '';
        }

        if (strpos($uaLower, 'windows nt') !== false) {
            return 'Windows';
        }
        if (strpos($uaLower, 'android') !== false) {
            return 'Android';
        }
        if (
            strpos($uaLower, 'iphone') !== false
            || strpos($uaLower, 'ipad') !== false
            || strpos($uaLower, 'ipod') !== false
        ) {
            return 'iOS';
        }
        if (strpos($uaLower, 'mac os x') !== false || strpos($uaLower, 'macintosh') !== false) {
            return 'macOS';
        }
        if (strpos($uaLower, 'linux') !== false) {
            return 'Linux';
        }

        return 'Unknown';
    }
}

if (!function_exists('cashhome_admin_loginlog_parse_float')) {
    function cashhome_admin_loginlog_parse_float(string $raw): ?float
    {
        $raw = trim($raw);
        if ($raw === '' || !is_numeric($raw)) {
            return null;
        }

        $value = (float)$raw;
        if (!is_finite($value)) {
            return null;
        }

        return $value;
    }
}

if (!function_exists('cashhome_admin_loginlog_collect_client_geo')) {
    function cashhome_admin_loginlog_collect_client_geo(): array
    {
        $latRaw = trim((string)($_POST['login_geo_latitude'] ?? ''));
        $lngRaw = trim((string)($_POST['login_geo_longitude'] ?? ''));
        $accuracyRaw = trim((string)($_POST['login_geo_accuracy'] ?? ''));
        $statusRaw = trim((string)($_POST['login_geo_status'] ?? ''));
        $sourceRaw = trim((string)($_POST['login_geo_source'] ?? ''));

        $lat = cashhome_admin_loginlog_parse_float($latRaw);
        $lng = cashhome_admin_loginlog_parse_float($lngRaw);
        $accuracy = cashhome_admin_loginlog_parse_float($accuracyRaw);

        if ($lat === null || $lng === null) {
            return [
                'latitude' => null,
                'longitude' => null,
                'accuracy' => null,
                'geo_status' => $statusRaw,
                'geo_source' => $sourceRaw,
                'location_text' => null,
            ];
        }

        if ($lat < -90.0 || $lat > 90.0 || $lng < -180.0 || $lng > 180.0) {
            return [
                'latitude' => null,
                'longitude' => null,
                'accuracy' => null,
                'geo_status' => 'error_out_of_range',
                'geo_source' => $sourceRaw,
                'location_text' => null,
            ];
        }

        if ($accuracy !== null && ($accuracy < 0.0 || $accuracy > 100000.0)) {
            $accuracy = null;
        }

        $locationText = 'GPS ' . number_format($lat, 6, '.', '') . ', ' . number_format($lng, 6, '.', '');
        if ($accuracy !== null) {
            $locationText .= ' (±' . number_format($accuracy, 1, '.', '') . 'm)';
        }

        return [
            'latitude' => $lat,
            'longitude' => $lng,
            'accuracy' => $accuracy,
            'geo_status' => $statusRaw,
            'geo_source' => $sourceRaw,
            'location_text' => mb_substr($locationText, 0, 255, 'UTF-8'),
        ];
    }
}

if (!function_exists('cashhome_admin_loginlog_is_public_ip')) {
    function cashhome_admin_loginlog_is_public_ip(string $ip): bool
    {
        if (!cashhome_admin_loginlog_is_valid_ip($ip)) {
            return false;
        }

        $validated = filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );

        return $validated !== false;
    }
}

if (!function_exists('cashhome_admin_loginlog_http_get_json')) {
    function cashhome_admin_loginlog_http_get_json(string $url): ?array
    {
        $url = trim($url);
        if ($url === '' || stripos($url, 'http') !== 0) {
            return null;
        }

        $raw = '';

        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            if ($ch !== false) {
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 2);
                curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
                curl_setopt($ch, CURLOPT_USERAGENT, 'CashhomeAdminLoginLog/1.0');
                $body = curl_exec($ch);

                $httpInfoKey = defined('CURLINFO_RESPONSE_CODE') ? CURLINFO_RESPONSE_CODE : CURLINFO_HTTP_CODE;
                $httpCode = (int)curl_getinfo($ch, $httpInfoKey);
                curl_close($ch);

                if (is_string($body) && $body !== '' && $httpCode >= 200 && $httpCode < 300) {
                    $raw = $body;
                }
            }
        }

        if ($raw === '') {
            $context = stream_context_create([
                'http' => [
                    'method' => 'GET',
                    'timeout' => 2,
                    'ignore_errors' => true,
                    'header' => "User-Agent: CashhomeAdminLoginLog/1.0\r\n",
                ],
                'ssl' => [
                    'verify_peer' => true,
                    'verify_peer_name' => true,
                ],
            ]);

            $body = @file_get_contents($url, false, $context);
            if (is_string($body) && $body !== '') {
                $raw = $body;
            }
        }

        if ($raw === '') {
            return null;
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return null;
        }

        return $decoded;
    }
}

if (!function_exists('cashhome_admin_loginlog_fetch_geo_by_ip')) {
    function cashhome_admin_loginlog_fetch_geo_by_ip(string $ip): array
    {
        if (!cashhome_admin_loginlog_is_public_ip($ip)) {
            return [];
        }

        $geo = [];

        $ipWhois = cashhome_admin_loginlog_http_get_json('https://ipwho.is/' . rawurlencode($ip));
        if (is_array($ipWhois) && (!isset($ipWhois['success']) || $ipWhois['success'] !== false)) {
            $country = trim((string)($ipWhois['country_code'] ?? ''));
            $region = trim((string)($ipWhois['region'] ?? ''));
            $city = trim((string)($ipWhois['city'] ?? ''));
            $timezone = '';
            if (isset($ipWhois['timezone']) && is_array($ipWhois['timezone'])) {
                $timezone = trim((string)($ipWhois['timezone']['id'] ?? ''));
            }

            $lat = cashhome_admin_loginlog_parse_float((string)($ipWhois['latitude'] ?? ''));
            $lng = cashhome_admin_loginlog_parse_float((string)($ipWhois['longitude'] ?? ''));

            $geo = [
                'country_code' => ($country !== '') ? mb_substr($country, 0, 8, 'UTF-8') : null,
                'region_name' => ($region !== '') ? mb_substr($region, 0, 120, 'UTF-8') : null,
                'city_name' => ($city !== '') ? mb_substr($city, 0, 120, 'UTF-8') : null,
                'latitude' => $lat,
                'longitude' => $lng,
                'timezone_name' => ($timezone !== '') ? mb_substr($timezone, 0, 64, 'UTF-8') : null,
            ];
        }

        if ($geo === []) {
            $ipApi = cashhome_admin_loginlog_http_get_json('https://ipapi.co/' . rawurlencode($ip) . '/json/');
            if (is_array($ipApi) && !isset($ipApi['error'])) {
                $country = trim((string)($ipApi['country_code'] ?? ''));
                $region = trim((string)($ipApi['region'] ?? ''));
                $city = trim((string)($ipApi['city'] ?? ''));
                $timezone = trim((string)($ipApi['timezone'] ?? ''));

                $lat = cashhome_admin_loginlog_parse_float((string)($ipApi['latitude'] ?? ''));
                $lng = cashhome_admin_loginlog_parse_float((string)($ipApi['longitude'] ?? ''));

                $geo = [
                    'country_code' => ($country !== '') ? mb_substr($country, 0, 8, 'UTF-8') : null,
                    'region_name' => ($region !== '') ? mb_substr($region, 0, 120, 'UTF-8') : null,
                    'city_name' => ($city !== '') ? mb_substr($city, 0, 120, 'UTF-8') : null,
                    'latitude' => $lat,
                    'longitude' => $lng,
                    'timezone_name' => ($timezone !== '') ? mb_substr($timezone, 0, 64, 'UTF-8') : null,
                ];
            }
        }

        return $geo;
    }
}

if (!function_exists('cashhome_admin_loginlog_collect_geo')) {
    function cashhome_admin_loginlog_collect_geo(string $ip = ''): array
    {
        $country = trim((string)($_SERVER['HTTP_CF_IPCOUNTRY'] ?? ($_SERVER['HTTP_GEOIP_COUNTRY_CODE'] ?? '')));
        $region = trim((string)($_SERVER['HTTP_CF_REGION'] ?? ($_SERVER['HTTP_GEOIP_REGION'] ?? '')));
        $city = trim((string)($_SERVER['HTTP_CF_IPCITY'] ?? ($_SERVER['HTTP_GEOIP_CITY'] ?? '')));
        $tz = trim((string)($_SERVER['HTTP_CF_TIMEZONE'] ?? ($_SERVER['HTTP_GEOIP_TIMEZONE'] ?? '')));

        $latRaw = trim((string)($_SERVER['HTTP_CF_LATITUDE'] ?? ($_SERVER['HTTP_X_LATITUDE'] ?? ($_SERVER['HTTP_GEOIP_LATITUDE'] ?? ''))));
        $lngRaw = trim((string)($_SERVER['HTTP_CF_LONGITUDE'] ?? ($_SERVER['HTTP_X_LONGITUDE'] ?? ($_SERVER['HTTP_GEOIP_LONGITUDE'] ?? ''))));

        $lat = cashhome_admin_loginlog_parse_float($latRaw);
        $lng = cashhome_admin_loginlog_parse_float($lngRaw);

        if (
            $country === ''
            && $region === ''
            && $city === ''
            && $lat === null
            && $lng === null
            && $ip !== ''
        ) {
            $fallback = cashhome_admin_loginlog_fetch_geo_by_ip($ip);
            if ($fallback !== []) {
                $country = (string)($fallback['country_code'] ?? '');
                $region = (string)($fallback['region_name'] ?? '');
                $city = (string)($fallback['city_name'] ?? '');
                $lat = isset($fallback['latitude']) ? cashhome_admin_loginlog_parse_float((string)$fallback['latitude']) : null;
                $lng = isset($fallback['longitude']) ? cashhome_admin_loginlog_parse_float((string)$fallback['longitude']) : null;

                if ($tz === '') {
                    $tz = (string)($fallback['timezone_name'] ?? '');
                }
            }
        }

        $parts = [];
        if ($city !== '') {
            $parts[] = $city;
        }
        if ($region !== '') {
            $parts[] = $region;
        }
        if ($country !== '') {
            $parts[] = $country;
        }

        $locationText = implode(', ', $parts);
        if ($locationText === '' && $ip !== '' && cashhome_admin_loginlog_is_valid_ip($ip)) {
            $locationText = $ip;
        }

        return [
            'country_code' => ($country !== '') ? mb_substr($country, 0, 8, 'UTF-8') : null,
            'region_name' => ($region !== '') ? mb_substr($region, 0, 120, 'UTF-8') : null,
            'city_name' => ($city !== '') ? mb_substr($city, 0, 120, 'UTF-8') : null,
            'latitude' => $lat,
            'longitude' => $lng,
            'timezone_name' => ($tz !== '') ? mb_substr($tz, 0, 64, 'UTF-8') : null,
            'location_text' => ($locationText !== '') ? mb_substr($locationText, 0, 255, 'UTF-8') : null,
        ];
    }
}

if (!function_exists('cashhome_admin_loginlog_table_exists')) {
    function cashhome_admin_loginlog_table_exists(PDO $pdo, string $tableName): bool
    {
        static $cache = [];

        $tableName = trim($tableName);
        if ($tableName === '') {
            return false;
        }

        if (array_key_exists($tableName, $cache)) {
            return (bool)$cache[$tableName];
        }

        try {
            $sql = 'SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = :table_name LIMIT 1';
            $stmt = $pdo->prepare($sql);
            $stmt->bindValue(':table_name', $tableName, PDO::PARAM_STR);
            $stmt->execute();
            $cache[$tableName] = ((int)$stmt->fetchColumn() === 1);
        } catch (Throwable $e) {
            $cache[$tableName] = false;
        }

        return (bool)$cache[$tableName];
    }
}

if (!function_exists('cashhome_admin_loginlog_insert')) {
    function cashhome_admin_loginlog_insert(PDO $pdo, array $payload): bool
    {
        $tableName = 'cashhome_1300_admin_login_log';
        if (!cashhome_admin_loginlog_table_exists($pdo, $tableName)) {
            return false;
        }

        $adminDbId = (int)($payload['admin_db_id'] ?? 0);
        if ($adminDbId <= 0) {
            return false;
        }

        $adminRole = strtolower(trim((string)($payload['admin_role'] ?? '')));
        if ($adminRole !== 'admin' && $adminRole !== 'master') {
            $adminRole = 'admin';
        }

        $adminUsername = trim((string)($payload['admin_username'] ?? $adminRole));
        $loginStatus = strtoupper(trim((string)($payload['login_status'] ?? 'SUCCESS')));
        if ($loginStatus !== 'SUCCESS' && $loginStatus !== 'FAIL') {
            $loginStatus = 'SUCCESS';
        }

        $ip = cashhome_admin_loginlog_pick_ip();
        $ua = trim((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));

        $deviceType = cashhome_admin_loginlog_detect_device_type();
        $browser = cashhome_admin_loginlog_detect_browser($ua);
        $osName = cashhome_admin_loginlog_detect_os($ua);

        $geo = cashhome_admin_loginlog_collect_geo($ip);
        $clientGeo = cashhome_admin_loginlog_collect_client_geo();

        if ($clientGeo['latitude'] !== null && $clientGeo['longitude'] !== null) {
            $geo['latitude'] = $clientGeo['latitude'];
            $geo['longitude'] = $clientGeo['longitude'];

            $existingLocation = trim((string)($geo['location_text'] ?? ''));
            $existingIsIp = ($existingLocation !== '' && cashhome_admin_loginlog_is_valid_ip($existingLocation));
            if ($existingLocation === '' || $existingIsIp) {
                $geo['location_text'] = $clientGeo['location_text'];
            } else {
                $geo['location_text'] = mb_substr($existingLocation . ' / GPS', 0, 255, 'UTF-8');
            }
        }

        $geoStatus = trim((string)($clientGeo['geo_status'] ?? ''));
        if ($geoStatus === '') {
            $geoStatus = 'server_geo';
        }

        $geoSource = trim((string)($clientGeo['geo_source'] ?? ''));
        if ($geoSource === '') {
            $geoSource = 'server_header_or_ip';
        }

        $referer = trim((string)($_SERVER['HTTP_REFERER'] ?? ''));
        $requestUri = trim((string)($_SERVER['REQUEST_URI'] ?? ''));

        try {
            $sql = 'INSERT INTO ' . $tableName . ' ('
                . 'cashhome_1300_admin_db_id, cashhome_1300_admin_role, cashhome_1300_admin_username, '
                . 'cashhome_1300_login_status, cashhome_1300_login_at, '
                . 'cashhome_1300_login_ip, cashhome_1300_user_agent, cashhome_1300_device_type, '
                . 'cashhome_1300_browser, cashhome_1300_os_name, '
                . 'cashhome_1300_country_code, cashhome_1300_region_name, cashhome_1300_city_name, '
                . 'cashhome_1300_latitude, cashhome_1300_longitude, cashhome_1300_timezone_name, '
                . 'cashhome_1300_location_text, cashhome_1300_geo_source, cashhome_1300_geo_status, '
                . 'cashhome_1300_referer_url, cashhome_1300_request_uri, cashhome_1300_created_at'
                . ') VALUES ('
                . ':admin_db_id, :admin_role, :admin_username, '
                . ':login_status, NOW(), '
                . ':login_ip, :user_agent, :device_type, '
                . ':browser, :os_name, '
                . ':country_code, :region_name, :city_name, '
                . ':latitude, :longitude, :timezone_name, '
                . ':location_text, :geo_source, :geo_status, '
                . ':referer_url, :request_uri, NOW()'
                . ')';

            $stmt = $pdo->prepare($sql);
            $stmt->bindValue(':admin_db_id', $adminDbId, PDO::PARAM_INT);
            $stmt->bindValue(':admin_role', mb_substr($adminRole, 0, 20, 'UTF-8'), PDO::PARAM_STR);
            $stmt->bindValue(':admin_username', mb_substr($adminUsername, 0, 50, 'UTF-8'), PDO::PARAM_STR);
            $stmt->bindValue(':login_status', $loginStatus, PDO::PARAM_STR);
            $stmt->bindValue(':login_ip', mb_substr($ip, 0, 45, 'UTF-8'), PDO::PARAM_STR);
            $stmt->bindValue(':user_agent', mb_substr($ua, 0, 700, 'UTF-8'), PDO::PARAM_STR);
            $stmt->bindValue(':device_type', mb_substr($deviceType, 0, 20, 'UTF-8'), PDO::PARAM_STR);
            $stmt->bindValue(':browser', mb_substr($browser, 0, 120, 'UTF-8'), PDO::PARAM_STR);
            $stmt->bindValue(':os_name', mb_substr($osName, 0, 120, 'UTF-8'), PDO::PARAM_STR);

            $stmt->bindValue(':country_code', $geo['country_code'], $geo['country_code'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
            $stmt->bindValue(':region_name', $geo['region_name'], $geo['region_name'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
            $stmt->bindValue(':city_name', $geo['city_name'], $geo['city_name'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);

            if ($geo['latitude'] === null) {
                $stmt->bindValue(':latitude', null, PDO::PARAM_NULL);
            } else {
                $stmt->bindValue(':latitude', (string)$geo['latitude'], PDO::PARAM_STR);
            }

            if ($geo['longitude'] === null) {
                $stmt->bindValue(':longitude', null, PDO::PARAM_NULL);
            } else {
                $stmt->bindValue(':longitude', (string)$geo['longitude'], PDO::PARAM_STR);
            }

            $stmt->bindValue(':timezone_name', $geo['timezone_name'], $geo['timezone_name'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
            $stmt->bindValue(':location_text', $geo['location_text'], $geo['location_text'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
            $stmt->bindValue(':geo_source', mb_substr($geoSource, 0, 40, 'UTF-8'), PDO::PARAM_STR);
            $stmt->bindValue(':geo_status', mb_substr($geoStatus, 0, 40, 'UTF-8'), PDO::PARAM_STR);
            $stmt->bindValue(':referer_url', $referer !== '' ? mb_substr($referer, 0, 1024, 'UTF-8') : null, $referer !== '' ? PDO::PARAM_STR : PDO::PARAM_NULL);
            $stmt->bindValue(':request_uri', $requestUri !== '' ? mb_substr($requestUri, 0, 1024, 'UTF-8') : null, $requestUri !== '' ? PDO::PARAM_STR : PDO::PARAM_NULL);

            return $stmt->execute();
        } catch (Throwable $e) {
            error_log('[cashhome_1300_admin_login_log insert fail] ' . $e->getMessage());
            return false;
        }
    }
}
