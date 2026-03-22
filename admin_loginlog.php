<?php

declare(strict_types=1);

session_start();
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/admin_login_log_common.php';

const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';
const LOGINLOG_GATE_TTL = 7200;
const LOGINLOG_GATE_SUFFIX = '12341234';
const ADMIN_LOGIN_LOG_TABLE = 'cashhome_1300_admin_login_log';

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function cashhome_pdo(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}

function loginlog_today_mmdd(): string
{
    return (new DateTimeImmutable('now', new DateTimeZone('Asia/Seoul')))->format('md');
}

function loginlog_expected_password(): string
{
    return loginlog_today_mmdd() . LOGINLOG_GATE_SUFFIX;
}

function is_loginlog_gate_authed(): bool
{
    if (empty($_SESSION['cashhome_loginlog_gate_authed']) || empty($_SESSION['cashhome_loginlog_gate_authed_at'])) {
        return false;
    }

    if ((time() - (int)$_SESSION['cashhome_loginlog_gate_authed_at']) > LOGINLOG_GATE_TTL) {
        return false;
    }

    $today = loginlog_today_mmdd();
    $authedDay = (string)($_SESSION['cashhome_loginlog_gate_day'] ?? '');
    if ($authedDay !== $today) {
        return false;
    }

    return true;
}

function normalize_date(string $value, string $fallback): string
{
    $value = trim($value);
    if ($value === '') {
        return $fallback;
    }

    $dt = DateTimeImmutable::createFromFormat('Y-m-d', $value);
    if (!$dt instanceof DateTimeImmutable) {
        return $fallback;
    }

    return $dt->format('Y-m-d');
}

function normalize_filters(array $input): array
{
    $now = new DateTimeImmutable('now', new DateTimeZone('Asia/Seoul'));
    $defaultTo = $now->format('Y-m-d');
    $defaultFrom = $now->modify('-6 days')->format('Y-m-d');

    $dateFrom = normalize_date((string)($input['date_from'] ?? ''), $defaultFrom);
    $dateTo = normalize_date((string)($input['date_to'] ?? ''), $defaultTo);

    if ($dateFrom > $dateTo) {
        $tmp = $dateFrom;
        $dateFrom = $dateTo;
        $dateTo = $tmp;
    }

    $status = strtoupper(trim((string)($input['status'] ?? '')));
    if ($status !== 'SUCCESS' && $status !== 'FAIL') {
        $status = '';
    }

    $adminRole = strtolower(trim((string)($input['admin_role'] ?? '')));
    if ($adminRole !== 'admin' && $adminRole !== 'master') {
        $adminRole = '';
    }

    $keyword = trim((string)($input['keyword'] ?? ''));
    if (mb_strlen($keyword, 'UTF-8') > 80) {
        $keyword = mb_substr($keyword, 0, 80, 'UTF-8');
    }

    $ipKeyword = trim((string)($input['ip_keyword'] ?? ''));
    if (mb_strlen($ipKeyword, 'UTF-8') > 80) {
        $ipKeyword = mb_substr($ipKeyword, 0, 80, 'UTF-8');
    }

    $page = (int)($input['page'] ?? 1);
    if ($page < 1) {
        $page = 1;
    }

    $perPage = (int)($input['per_page'] ?? 50);
    if (!in_array($perPage, [20, 50, 100, 200], true)) {
        $perPage = 50;
    }

    return [
        'date_from' => $dateFrom,
        'date_to' => $dateTo,
        'status' => $status,
        'admin_role' => $adminRole,
        'keyword' => $keyword,
        'ip_keyword' => $ipKeyword,
        'page' => $page,
        'per_page' => $perPage,
    ];
}

function build_where(array $filters): array
{
    $where = ['1=1'];
    $params = [];

    if (!empty($filters['date_from'])) {
        $where[] = 'l.cashhome_1300_login_at >= :date_from';
        $params[':date_from'] = (string)$filters['date_from'] . ' 00:00:00';
    }

    if (!empty($filters['date_to'])) {
        $to = DateTimeImmutable::createFromFormat('Y-m-d', (string)$filters['date_to']);
        if ($to instanceof DateTimeImmutable) {
            $next = $to->modify('+1 day');
            $where[] = 'l.cashhome_1300_login_at < :date_to_next';
            $params[':date_to_next'] = $next->format('Y-m-d') . ' 00:00:00';
        }
    }

    if (!empty($filters['status'])) {
        $where[] = 'l.cashhome_1300_login_status = :login_status';
        $params[':login_status'] = (string)$filters['status'];
    }

    if (!empty($filters['admin_role'])) {
        $where[] = 'l.cashhome_1300_admin_role = :admin_role';
        $params[':admin_role'] = (string)$filters['admin_role'];
    }

    if (!empty($filters['keyword'])) {
        $where[] = '('
            . 'l.cashhome_1300_admin_username LIKE :keyword_name '
            . 'OR CAST(l.cashhome_1300_admin_db_id AS CHAR) LIKE :keyword_id'
            . ')';
        $like = '%' . (string)$filters['keyword'] . '%';
        $params[':keyword_name'] = $like;
        $params[':keyword_id'] = $like;
    }

    if (!empty($filters['ip_keyword'])) {
        $where[] = 'l.cashhome_1300_login_ip LIKE :ip_keyword';
        $params[':ip_keyword'] = '%' . (string)$filters['ip_keyword'] . '%';
    }

    return [
        'sql' => implode(' AND ', $where),
        'params' => $params,
    ];
}

function bind_where_params(PDOStatement $stmt, array $params): void
{
    foreach ($params as $key => $value) {
        if (is_int($value)) {
            $stmt->bindValue((string)$key, $value, PDO::PARAM_INT);
        } else {
            $stmt->bindValue((string)$key, (string)$value, PDO::PARAM_STR);
        }
    }
}

function build_location_text(array $row): string
{
    $locationText = trim((string)($row['cashhome_1300_location_text'] ?? ''));
    if ($locationText !== '') {
        return $locationText;
    }

    $parts = array_filter([
        (string)($row['cashhome_1300_city_name'] ?? ''),
        (string)($row['cashhome_1300_region_name'] ?? ''),
        (string)($row['cashhome_1300_country_code'] ?? ''),
    ]);

    return $parts !== [] ? implode(', ', $parts) : '-';
}

function admin_label_from_id(int $id): string
{
    return match ($id) {
        1 => 'master',
        2 => 'admin',
        default => $id > 0 ? ('admin#' . $id) : '-',
    };
}

function fetch_summary(PDO $pdo, array $whereBundle): array
{
    $empty = [
        'total_count' => 0,
        'success_count' => 0,
        'fail_count' => 0,
        'admin_count' => 0,
        'ip_count' => 0,
    ];

    if (!cashhome_admin_loginlog_table_exists($pdo, ADMIN_LOGIN_LOG_TABLE)) {
        return $empty;
    }

    $sql = 'SELECT '
        . 'COUNT(*) AS total_count, '
        . 'SUM(CASE WHEN l.cashhome_1300_login_status = "SUCCESS" THEN 1 ELSE 0 END) AS success_count, '
        . 'SUM(CASE WHEN l.cashhome_1300_login_status = "FAIL" THEN 1 ELSE 0 END) AS fail_count, '
        . 'COUNT(DISTINCT l.cashhome_1300_admin_db_id) AS admin_count, '
        . 'COUNT(DISTINCT l.cashhome_1300_login_ip) AS ip_count '
        . 'FROM ' . ADMIN_LOGIN_LOG_TABLE . ' l '
        . 'WHERE ' . $whereBundle['sql'];

    $stmt = $pdo->prepare($sql);
    bind_where_params($stmt, $whereBundle['params']);
    $stmt->execute();
    $row = $stmt->fetch();

    if (!is_array($row)) {
        return $empty;
    }

    return [
        'total_count' => (int)($row['total_count'] ?? 0),
        'success_count' => (int)($row['success_count'] ?? 0),
        'fail_count' => (int)($row['fail_count'] ?? 0),
        'admin_count' => (int)($row['admin_count'] ?? 0),
        'ip_count' => (int)($row['ip_count'] ?? 0),
    ];
}

function count_rows(PDO $pdo, array $whereBundle): int
{
    if (!cashhome_admin_loginlog_table_exists($pdo, ADMIN_LOGIN_LOG_TABLE)) {
        return 0;
    }

    $sql = 'SELECT COUNT(*) FROM ' . ADMIN_LOGIN_LOG_TABLE . ' l WHERE ' . $whereBundle['sql'];
    $stmt = $pdo->prepare($sql);
    bind_where_params($stmt, $whereBundle['params']);
    $stmt->execute();
    return (int)$stmt->fetchColumn();
}

function fetch_rows(PDO $pdo, array $whereBundle, int $page, int $perPage): array
{
    if (!cashhome_admin_loginlog_table_exists($pdo, ADMIN_LOGIN_LOG_TABLE)) {
        return [];
    }

    $limit = max(20, min(200, $perPage));
    $offset = max(0, ($page - 1) * $limit);

    $sql = 'SELECT '
        . 'l.cashhome_1300_id, '
        . 'l.cashhome_1300_admin_db_id, '
        . 'l.cashhome_1300_admin_role, '
        . 'l.cashhome_1300_admin_username, '
        . 'l.cashhome_1300_login_status, '
        . 'l.cashhome_1300_login_at, '
        . 'l.cashhome_1300_login_ip, '
        . 'l.cashhome_1300_user_agent, '
        . 'l.cashhome_1300_device_type, '
        . 'l.cashhome_1300_browser, '
        . 'l.cashhome_1300_os_name, '
        . 'l.cashhome_1300_country_code, '
        . 'l.cashhome_1300_region_name, '
        . 'l.cashhome_1300_city_name, '
        . 'l.cashhome_1300_latitude, '
        . 'l.cashhome_1300_longitude, '
        . 'l.cashhome_1300_location_text, '
        . 'l.cashhome_1300_request_uri '
        . 'FROM ' . ADMIN_LOGIN_LOG_TABLE . ' l '
        . 'WHERE ' . $whereBundle['sql'] . ' '
        . 'ORDER BY l.cashhome_1300_login_at DESC, l.cashhome_1300_id DESC '
        . 'LIMIT :limit OFFSET :offset';

    $stmt = $pdo->prepare($sql);
    bind_where_params($stmt, $whereBundle['params']);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();

    $rows = $stmt->fetchAll();
    return is_array($rows) ? $rows : [];
}

function fetch_timeline_admins(PDO $pdo, array $whereBundle): array
{
    if (!cashhome_admin_loginlog_table_exists($pdo, ADMIN_LOGIN_LOG_TABLE)) {
        return [];
    }

    $sql = 'SELECT '
        . 'l.cashhome_1300_admin_db_id, '
        . 'COALESCE(NULLIF(MAX(NULLIF(l.cashhome_1300_admin_username, "")), ""), CONCAT("관리자#", l.cashhome_1300_admin_db_id)) AS admin_username, '
        . 'LOWER(COALESCE(NULLIF(MAX(NULLIF(l.cashhome_1300_admin_role, "")), ""), "admin")) AS admin_role, '
        . 'COUNT(*) AS login_count, '
        . 'MAX(l.cashhome_1300_login_at) AS last_login_at, '
        . 'SUM(CASE WHEN l.cashhome_1300_latitude IS NOT NULL AND l.cashhome_1300_longitude IS NOT NULL THEN 1 ELSE 0 END) AS coordinate_count '
        . 'FROM ' . ADMIN_LOGIN_LOG_TABLE . ' l '
        . 'WHERE ' . $whereBundle['sql'] . ' '
        . 'GROUP BY l.cashhome_1300_admin_db_id '
        . 'ORDER BY last_login_at DESC, login_count DESC, l.cashhome_1300_admin_db_id ASC '
        . 'LIMIT 1000';

    $stmt = $pdo->prepare($sql);
    bind_where_params($stmt, $whereBundle['params']);
    $stmt->execute();
    $rows = $stmt->fetchAll();

    return is_array($rows) ? $rows : [];
}

function fetch_timeline_points(PDO $pdo, array $whereBundle, int $timelineAdminId): array
{
    if ($timelineAdminId <= 0 || !cashhome_admin_loginlog_table_exists($pdo, ADMIN_LOGIN_LOG_TABLE)) {
        return [
            'admin' => [],
            'points' => [],
            'total_count' => 0,
            'coordinate_count' => 0,
        ];
    }

    $whereSql = $whereBundle['sql'] . ' AND l.cashhome_1300_admin_db_id = :timeline_admin_id';
    $params = $whereBundle['params'];
    $params[':timeline_admin_id'] = $timelineAdminId;

    $sql = 'SELECT '
        . 'l.cashhome_1300_id, '
        . 'l.cashhome_1300_admin_db_id, '
        . 'l.cashhome_1300_admin_role, '
        . 'l.cashhome_1300_admin_username, '
        . 'l.cashhome_1300_login_status, '
        . 'l.cashhome_1300_login_at, '
        . 'l.cashhome_1300_login_ip, '
        . 'l.cashhome_1300_device_type, '
        . 'l.cashhome_1300_browser, '
        . 'l.cashhome_1300_os_name, '
        . 'l.cashhome_1300_country_code, '
        . 'l.cashhome_1300_region_name, '
        . 'l.cashhome_1300_city_name, '
        . 'l.cashhome_1300_latitude, '
        . 'l.cashhome_1300_longitude, '
        . 'l.cashhome_1300_location_text, '
        . 'l.cashhome_1300_request_uri '
        . 'FROM ' . ADMIN_LOGIN_LOG_TABLE . ' l '
        . 'WHERE ' . $whereSql . ' '
        . 'ORDER BY l.cashhome_1300_login_at ASC, l.cashhome_1300_id ASC '
        . 'LIMIT 3000';

    $stmt = $pdo->prepare($sql);
    bind_where_params($stmt, $params);
    $stmt->execute();
    $rows = $stmt->fetchAll();

    if (!is_array($rows) || $rows === []) {
        return [
            'admin' => [],
            'points' => [],
            'total_count' => 0,
            'coordinate_count' => 0,
        ];
    }

    $first = $rows[0];
    $adminName = trim((string)($first['cashhome_1300_admin_username'] ?? ''));
    if ($adminName === '') {
        $adminName = admin_label_from_id((int)($first['cashhome_1300_admin_db_id'] ?? 0));
    }

    $adminInfo = [
        'admin_db_id' => (int)($first['cashhome_1300_admin_db_id'] ?? $timelineAdminId),
        'admin_name' => $adminName,
        'admin_role' => strtolower(trim((string)($first['cashhome_1300_admin_role'] ?? 'admin'))),
    ];

    $points = [];
    $coordinateCount = 0;

    foreach ($rows as $index => $row) {
        $latRaw = trim((string)($row['cashhome_1300_latitude'] ?? ''));
        $lngRaw = trim((string)($row['cashhome_1300_longitude'] ?? ''));

        $hasCoordinates = ($latRaw !== '' && $lngRaw !== '' && is_numeric($latRaw) && is_numeric($lngRaw));
        $latValue = null;
        $lngValue = null;

        if ($hasCoordinates) {
            $latValue = (float)$latRaw;
            $lngValue = (float)$lngRaw;
            $coordinateCount += 1;
        }

        $points[] = [
            'seq' => $index + 1,
            'login_log_id' => (int)($row['cashhome_1300_id'] ?? 0),
            'login_at' => (string)($row['cashhome_1300_login_at'] ?? ''),
            'login_status' => strtoupper((string)($row['cashhome_1300_login_status'] ?? '')),
            'login_ip' => (string)($row['cashhome_1300_login_ip'] ?? ''),
            'device_type' => (string)($row['cashhome_1300_device_type'] ?? ''),
            'browser' => (string)($row['cashhome_1300_browser'] ?? ''),
            'os_name' => (string)($row['cashhome_1300_os_name'] ?? ''),
            'location_text' => build_location_text($row),
            'latitude' => $latValue,
            'longitude' => $lngValue,
            'has_coordinates' => $hasCoordinates,
            'request_uri' => (string)($row['cashhome_1300_request_uri'] ?? ''),
        ];
    }

    return [
        'admin' => $adminInfo,
        'points' => $points,
        'total_count' => count($points),
        'coordinate_count' => $coordinateCount,
    ];
}

$action = trim((string)($_GET['action'] ?? ''));

if (isset($_GET['gate_logout']) && $_GET['gate_logout'] === '1') {
    unset(
        $_SESSION['cashhome_loginlog_gate_authed'],
        $_SESSION['cashhome_loginlog_gate_authed_at'],
        $_SESSION['cashhome_loginlog_gate_day']
    );
    header('Location: admin_loginlog.php');
    exit;
}

if (!is_loginlog_gate_authed()) {
    if ($action === 'timeline_points') {
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode([
            'ok' => false,
            'message' => '페이지 접근 비밀번호 인증이 필요합니다.',
            'admin' => [],
            'points' => [],
            'total_count' => 0,
            'coordinate_count' => 0,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    $gateError = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $submitted = trim((string)($_POST['gate_password'] ?? ''));
        $expected = loginlog_expected_password();
        if ($submitted !== '' && hash_equals($expected, $submitted)) {
            $_SESSION['cashhome_loginlog_gate_authed'] = true;
            $_SESSION['cashhome_loginlog_gate_authed_at'] = time();
            $_SESSION['cashhome_loginlog_gate_day'] = loginlog_today_mmdd();
            header('Location: admin_loginlog.php');
            exit;
        }
        $gateError = '비밀번호가 올바르지 않습니다.';
    }
    ?>
    <!doctype html>
    <html lang="ko">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>로그인 로그 접근</title>
        <style>
            body { margin:0; font-family:"Noto Sans KR",system-ui,sans-serif; background:#0b1220; color:#eaf0ff; }
            .wrap { max-width:420px; margin:0 auto; padding:28px 16px; }
            .card { background:rgba(16,26,51,.85); border:1px solid rgba(234,240,255,.12); border-radius:18px; padding:18px; }
            h2 { margin:0 0 8px; }
            .hint { margin:0 0 12px; font-size:12px; color:#9db0d0; line-height:1.5; }
            label { display:block; margin-bottom:6px; font-size:12px; color:#9db0d0; }
            input { width:100%; box-sizing:border-box; height:42px; border-radius:12px; border:1px solid rgba(234,240,255,.14); background:rgba(8,12,24,.55); color:#eaf0ff; padding:0 12px; }
            button { margin-top:12px; width:100%; height:42px; border:0; border-radius:999px; font-weight:900; cursor:pointer; background:linear-gradient(135deg,#35d5ff,#8b8cff); color:#061025; }
            .err { margin-top:10px; border-radius:12px; padding:10px; border:1px solid rgba(255,120,120,.4); background:rgba(255,255,255,.03); color:#ffdede; font-size:12px; }
            .tiny { margin-top:10px; color:#9db0d0; font-size:12px; }
            a { color:#9db0d0; text-decoration:none; }
        </style>
    </head>
    <body>
    <div class="wrap">
        <div class="card">
            <h2>로그인 위치이력 접근</h2>
             <p 12341234</b><br>예: 3월 22일이면 <b></b></p>
            <form method="post" action="admin_loginlog.php" autocomplete="off">
                <label for="gate_password">접근 비밀번호</label>
                <input id="gate_password" name="gate_password" type="password" inputmode="numeric" required autofocus>
                <button type="submit">입장</button>
            </form>
            <?php if ($gateError !== ''): ?>
                <div class="err"><?= h($gateError) ?></div>
            <?php endif; ?>
            <div class="tiny"><a href="./">← 홈으로</a></div>
        </div>
    </div>
    </body>
    </html>
    <?php
    exit;
}

$currentAdminRole = strtolower(trim((string)($_SESSION['cashhome_admin_role'] ?? '')));
if ($currentAdminRole === '') {
    $currentAdminRole = '-';
}
$currentAdminDbId = (int)($_SESSION['cashhome_admin_id'] ?? 0);

$filters = normalize_filters($_GET);
$whereBundle = build_where($filters);

if ($action === 'timeline_points') {
    $payload = [
        'ok' => false,
        'message' => '',
        'admin' => [],
        'points' => [],
        'total_count' => 0,
        'coordinate_count' => 0,
    ];

    try {
        $pdo = cashhome_pdo();
        if (!cashhome_admin_loginlog_table_exists($pdo, ADMIN_LOGIN_LOG_TABLE)) {
            $payload['message'] = ADMIN_LOGIN_LOG_TABLE . ' 테이블이 없습니다.';
        } else {
            $timelineAdminId = (int)($_GET['timeline_admin_id'] ?? ($_GET['timeline_user_id'] ?? 0));
            if ($timelineAdminId <= 0) {
                $payload['message'] = '관리자를 선택해주세요.';
            } else {
                $bundle = fetch_timeline_points($pdo, $whereBundle, $timelineAdminId);
                $payload['ok'] = true;
                $payload['admin'] = $bundle['admin'];
                $payload['points'] = $bundle['points'];
                $payload['total_count'] = $bundle['total_count'];
                $payload['coordinate_count'] = $bundle['coordinate_count'];
            }
        }
    } catch (Throwable $e) {
        $payload['message'] = '타임라인 조회 중 오류가 발생했습니다.';
    }

    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

$errorMessage = '';
$summary = [
    'total_count' => 0,
    'success_count' => 0,
    'fail_count' => 0,
    'admin_count' => 0,
    'ip_count' => 0,
];
$rows = [];
$totalCount = 0;
$timelineAdmins = [];

try {
    $pdo = cashhome_pdo();
    if (!cashhome_admin_loginlog_table_exists($pdo, ADMIN_LOGIN_LOG_TABLE)) {
        $errorMessage = ADMIN_LOGIN_LOG_TABLE . ' 테이블이 없습니다. 먼저 SQL을 실행해주세요.';
    } else {
        $totalCount = count_rows($pdo, $whereBundle);
        $summary = fetch_summary($pdo, $whereBundle);
        $timelineAdmins = fetch_timeline_admins($pdo, $whereBundle);

        $totalPages = max(1, (int)ceil($totalCount / max(1, (int)$filters['per_page'])));
        if ((int)$filters['page'] > $totalPages) {
            $filters['page'] = $totalPages;
        }

        $rows = fetch_rows($pdo, $whereBundle, (int)$filters['page'], (int)$filters['per_page']);
    }
} catch (Throwable $e) {
    $errorMessage = '로그인 로그 조회 중 오류가 발생했습니다: ' . $e->getMessage();
}

$selectedTimelineAdminId = (int)($_GET['timeline_admin_id'] ?? 0);
$timelineAdminIdSet = [];
foreach ($timelineAdmins as $adminRow) {
    $aid = (int)($adminRow['cashhome_1300_admin_db_id'] ?? 0);
    if ($aid > 0) {
        $timelineAdminIdSet[$aid] = true;
    }
}
if ($selectedTimelineAdminId <= 0 || !isset($timelineAdminIdSet[$selectedTimelineAdminId])) {
    $selectedTimelineAdminId = count($timelineAdmins) > 0
        ? (int)($timelineAdmins[0]['cashhome_1300_admin_db_id'] ?? 0)
        : 0;
}

$totalPages = max(1, (int)ceil($totalCount / max(1, (int)$filters['per_page'])));
$currentPage = (int)$filters['page'];
if ($currentPage < 1) {
    $currentPage = 1;
}
if ($currentPage > $totalPages) {
    $currentPage = $totalPages;
}

$baseParams = [
    'date_from' => (string)$filters['date_from'],
    'date_to' => (string)$filters['date_to'],
    'status' => (string)$filters['status'],
    'admin_role' => (string)$filters['admin_role'],
    'keyword' => (string)$filters['keyword'],
    'ip_keyword' => (string)$filters['ip_keyword'],
    'per_page' => (string)$filters['per_page'],
];

function build_url(array $params): string
{
    return 'admin_loginlog.php?' . http_build_query($params);
}

$resetUrl = build_url([]);
$prevUrl = build_url(array_merge($baseParams, ['page' => max(1, $currentPage - 1)]));
$nextUrl = build_url(array_merge($baseParams, ['page' => min($totalPages, $currentPage + 1)]));
$timelineApiUrl = build_url(array_merge($baseParams, ['action' => 'timeline_points']));
?>
<!doctype html>
<html lang="ko">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>관리자 로그인 위치이력</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin="">
    <style>
        body {
            margin: 0;
            font-family: "Noto Sans KR", system-ui, -apple-system, sans-serif;
            background: #0b1220;
            color: #eaf0ff;
        }

        .wrap {
            max-width: 1380px;
            margin: 0 auto;
            padding: 18px;
        }

        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 14px;
            margin-bottom: 14px;
        }

        .title h2 {
            margin: 0;
            font-size: 28px;
            font-weight: 900;
            letter-spacing: -.3px;
        }

        .muted {
            margin-top: 6px;
            color: #9db0d0;
            font-size: 13px;
        }

        .headerRight {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
            justify-content: flex-end;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border: 1px solid rgba(234, 240, 255, .16);
            border-radius: 12px;
            color: #eaf0ff;
            background: rgba(255, 255, 255, .04);
            text-decoration: none;
            padding: 8px 12px;
            cursor: pointer;
            font-weight: 800;
            font-size: 12px;
            transition: .18s ease;
        }

        .btn:hover {
            background: rgba(255, 255, 255, .08);
        }

        .btn.primary {
            background: linear-gradient(135deg, #35d5ff, #8b8cff);
            color: #081328;
            border: none;
        }

        .btn[aria-disabled="true"] {
            pointer-events: none;
            opacity: .45;
        }

        .adminChip {
            border-radius: 999px;
            background: rgba(255, 255, 255, .09);
            border-color: rgba(234, 240, 255, .2);
        }

        .loginlog-card {
            background: rgba(16, 26, 51, .82);
            border: 1px solid rgba(234, 240, 255, .12);
            border-radius: 16px;
            padding: 14px;
            box-sizing: border-box;
        }

        .loginlog-filter {
            display: grid;
            grid-template-columns: repeat(7, minmax(120px, 1fr));
            gap: 10px;
            margin-bottom: 12px;
        }

        .loginlog-filter label {
            display: flex;
            flex-direction: column;
            gap: 6px;
            font-size: 12px;
            color: #9db0d0;
        }

        .loginlog-filter input,
        .loginlog-filter select {
            width: 100%;
            height: 38px;
            border-radius: 10px;
            border: 1px solid rgba(234, 240, 255, .16);
            background: rgba(8, 12, 24, .55);
            color: #eaf0ff;
            padding: 0 10px;
            box-sizing: border-box;
            outline: none;
            font-size: 13px;
        }

        .loginlog-filter .filter-actions {
            display: flex;
            gap: 8px;
            align-items: end;
        }

        .loginlog-error {
            border: 1px solid rgba(255, 120, 120, .5);
            color: #ffdede;
            margin-bottom: 12px;
        }

        .loginlog-summary {
            display: grid;
            grid-template-columns: repeat(3, minmax(160px, 1fr));
            gap: 10px;
            margin-bottom: 12px;
        }

        .stat h3 {
            margin: 0;
            font-size: 13px;
            color: #9db0d0;
        }

        .stat p {
            margin: 8px 0 0;
            font-size: 24px;
            font-weight: 900;
            color: #f3f7ff;
        }

        .table-wrap {
            overflow: hidden;
            padding: 0;
        }

        .table-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 14px;
            border-bottom: 1px solid rgba(234, 240, 255, .12);
        }

        .table-head h2 {
            margin: 0;
            font-size: 18px;
        }

        .table-head-right {
            display: flex;
            align-items: center;
            gap: 12px;
            color: #9db0d0;
            font-size: 12px;
        }

        .loginlog-tabs {
            display: inline-flex;
            border: 1px solid rgba(234, 240, 255, .14);
            border-radius: 999px;
            overflow: hidden;
        }

        .loginlog-tab {
            border: 0;
            background: transparent;
            color: #b8c8e6;
            font-size: 12px;
            font-weight: 800;
            padding: 8px 12px;
            cursor: pointer;
        }

        .loginlog-tab.is-active {
            background: rgba(53, 213, 255, .22);
            color: #eaf0ff;
        }

        .loginlog-tab-panel {
            display: none;
        }

        .loginlog-tab-panel.is-active {
            display: block;
        }

        .table-scroll {
            overflow: auto;
            max-height: 520px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 980px;
        }

        th,
        td {
            border-top: 1px solid rgba(234, 240, 255, .08);
            padding: 10px;
            text-align: left;
            vertical-align: top;
            font-size: 12px;
        }

        th {
            position: sticky;
            top: 0;
            z-index: 2;
            background: #111b34;
            color: #b9cae9;
            font-weight: 800;
        }

        .empty {
            text-align: center;
            color: #95a8ca;
            padding: 20px;
        }

        .status {
            display: inline-flex;
            padding: 3px 8px;
            border-radius: 999px;
            font-weight: 800;
            font-size: 11px;
        }

        .status-success {
            background: rgba(56, 189, 145, .22);
            color: #98ffd9;
        }

        .status-fail {
            background: rgba(248, 113, 113, .2);
            color: #ffc5c5;
        }

        .user-main {
            font-weight: 800;
            color: #f3f7ff;
        }

        .user-sub {
            margin-top: 4px;
            color: #9db0d0;
            font-size: 11px;
        }

        .map-na {
            color: #7f94bb;
            font-size: 11px;
        }

        .table-pagination {
            display: flex;
            justify-content: center;
            gap: 10px;
            align-items: center;
            padding: 12px;
            border-top: 1px solid rgba(234, 240, 255, .1);
            color: #9db0d0;
            font-size: 12px;
        }

        .timeline-toolbar {
            display: flex;
            gap: 10px;
            align-items: end;
            padding: 12px 14px;
            border-bottom: 1px solid rgba(234, 240, 255, .1);
        }

        .timeline-user-field {
            display: flex;
            flex-direction: column;
            gap: 6px;
            width: min(520px, 100%);
            font-size: 12px;
            color: #9db0d0;
        }

        .timeline-user-field select {
            width: 100%;
            height: 38px;
            border-radius: 10px;
            border: 1px solid rgba(234, 240, 255, .16);
            background: rgba(8, 12, 24, .55);
            color: #eaf0ff;
            padding: 0 10px;
        }

        .timeline-userlist-scroll {
            max-height: 250px;
            overflow: auto;
            border-bottom: 1px solid rgba(234, 240, 255, .1);
        }

        .timeline-userlist-table {
            min-width: 860px;
        }

        .timeline-userlist-table tr.is-selected {
            background: rgba(53, 213, 255, .13);
        }

        .timeline-map-wrap {
            display: grid;
            grid-template-columns: minmax(320px, 1.15fr) minmax(280px, .85fr);
            gap: 10px;
            padding: 12px;
        }

        .timeline-map {
            min-height: 460px;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid rgba(234, 240, 255, .16);
            background: #0f1b37;
        }

        .timeline-side {
            border: 1px solid rgba(234, 240, 255, .14);
            border-radius: 12px;
            padding: 10px;
            background: rgba(8, 12, 24, .44);
            display: flex;
            flex-direction: column;
            min-height: 460px;
        }

        .timeline-side h3 {
            margin: 0;
            font-size: 15px;
        }

        .timeline-meta {
            margin: 8px 0 10px;
            color: #9db0d0;
            font-size: 12px;
            line-height: 1.5;
        }

        .timeline-point-list {
            list-style: none;
            margin: 0;
            padding: 0;
            overflow: auto;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .timeline-point-item {
            border: 1px solid rgba(234, 240, 255, .12);
            border-radius: 10px;
            background: rgba(255, 255, 255, .02);
            padding: 8px;
        }

        .timeline-point-item.has-coord {
            border-color: rgba(76, 195, 255, .5);
        }

        .timeline-point-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: #b5c7e8;
        }

        .timeline-point-head strong {
            color: #fff;
        }

        .timeline-point-sub {
            margin-top: 3px;
            color: #9db0d0;
            font-size: 11px;
        }

        .timeline-jump {
            padding: 4px 7px;
            border-radius: 8px;
            font-size: 11px;
        }

        .timeline-map-empty {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            height: 100%;
            color: #9db0d0;
            font-size: 12px;
        }

        .timeline-time-label {
            background: rgba(11, 18, 32, .92);
            color: #eaf0ff;
            border: 1px solid rgba(234, 240, 255, .2);
            border-radius: 6px;
            padding: 2px 6px;
            font-size: 10px;
            font-weight: 800;
        }

        .loginlog-map-modal {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, .6);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            padding: 14px;
        }

        .loginlog-map-modal[hidden] {
            display: none !important;
        }

        .loginlog-map-dialog {
            width: min(920px, 100%);
            max-height: 88vh;
            overflow: auto;
            border-radius: 14px;
            background: #0d1831;
            border: 1px solid rgba(234, 240, 255, .18);
            padding: 12px;
        }

        .loginlog-map-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            margin-bottom: 8px;
        }

        .loginlog-map-head h3 {
            margin: 0;
        }

        .loginlog-map-meta {
            margin: 0 0 8px;
            color: #9db0d0;
            font-size: 12px;
            line-height: 1.5;
        }

        .loginlog-map-frame-wrap {
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid rgba(234, 240, 255, .16);
            background: #091227;
            height: min(62vh, 520px);
        }

        .loginlog-map-frame {
            width: 100%;
            height: 100%;
            border: 0;
            background: #091227;
        }

        .loginlog-map-actions {
            display: flex;
            justify-content: flex-end;
            gap: 8px;
            margin-top: 10px;
        }

        body.loginlog-modal-open {
            overflow: hidden;
        }

        @media (max-width: 1180px) {
            .loginlog-filter {
                grid-template-columns: repeat(4, minmax(120px, 1fr));
            }

            .timeline-map-wrap {
                grid-template-columns: 1fr;
            }

            .timeline-map,
            .timeline-side {
                min-height: 360px;
            }
        }

        @media (max-width: 860px) {
            .topbar {
                flex-direction: column;
                align-items: flex-start;
            }

            .headerRight {
                justify-content: flex-start;
            }

            .loginlog-filter {
                grid-template-columns: repeat(2, minmax(120px, 1fr));
            }

            .loginlog-summary {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
<div class="wrap">
    <div class="topbar">
        <div class="title">
            <h2>관리자 로그인 위치이력</h2>
            <div class="muted">로그인 시 접속 위치/IP/기기 정보를 조회하고 사용자별 이동 타임라인을 확인합니다.</div>
        </div>
        <div class="headerRight">
            <span class="btn adminChip">
                관리자:
                <b><?= h($currentAdminRole) ?></b>
                <?php if ($currentAdminDbId > 0): ?>
                    <span style="opacity:.85; margin-left:6px;">(#<?= h((string)$currentAdminDbId) ?>)</span>
                <?php endif; ?>
            </span>
            <a class="btn" href="admin_inquiries.php">접수이력으로</a>
            <a class="btn" href="admin_inquiries.php?logout=1">LOG OUT</a>
            <a class="btn" href="admin_loginlog.php?gate_logout=1">페이지 잠금</a>
        </div>
    </div>

    <form class="loginlog-card loginlog-filter js-loginlog-filter" method="get" action="admin_loginlog.php" autocomplete="off">
        <input type="hidden" name="page" value="1" class="js-page-input">

        <label>
            <span>시작일</span>
            <input type="date" name="date_from" value="<?= h((string)$filters['date_from']) ?>">
        </label>

        <label>
            <span>종료일</span>
            <input type="date" name="date_to" value="<?= h((string)$filters['date_to']) ?>">
        </label>

        <label>
            <span>상태</span>
            <select name="status">
                <option value="" <?= $filters['status'] === '' ? 'selected' : '' ?>>전체</option>
                <option value="SUCCESS" <?= $filters['status'] === 'SUCCESS' ? 'selected' : '' ?>>SUCCESS</option>
                <option value="FAIL" <?= $filters['status'] === 'FAIL' ? 'selected' : '' ?>>FAIL</option>
            </select>
        </label>

        <label>
            <span>관리자 권한</span>
            <select name="admin_role">
                <option value="" <?= $filters['admin_role'] === '' ? 'selected' : '' ?>>전체</option>
                <option value="admin" <?= $filters['admin_role'] === 'admin' ? 'selected' : '' ?>>admin</option>
                <option value="master" <?= $filters['admin_role'] === 'master' ? 'selected' : '' ?>>master</option>
            </select>
        </label>

        <label>
            <span>관리자 검색</span>
            <input type="text" name="keyword" value="<?= h((string)$filters['keyword']) ?>" placeholder="이름/아이디/번호">
        </label>

        <label>
            <span>IP 검색</span>
            <input type="text" name="ip_keyword" value="<?= h((string)$filters['ip_keyword']) ?>" placeholder="접속 IP">
        </label>

        <label>
            <span>행수</span>
            <select name="per_page">
                <?php foreach ([20, 50, 100, 200] as $size): ?>
                    <option value="<?= $size ?>" <?= (int)$filters['per_page'] === $size ? 'selected' : '' ?>><?= $size ?></option>
                <?php endforeach; ?>
            </select>
        </label>

        <div class="filter-actions">
            <button type="submit" class="btn primary">조회</button>
            <a class="btn" href="<?= h($resetUrl) ?>">초기화</a>
        </div>
    </form>

    <?php if ($errorMessage !== ''): ?>
        <div class="loginlog-card loginlog-error"><?= h($errorMessage) ?></div>
    <?php endif; ?>

    <section class="loginlog-summary">
        <article class="loginlog-card stat">
            <h3>조회 건수</h3>
            <p><?= number_format((int)$summary['total_count']) ?>건</p>
        </article>
        <article class="loginlog-card stat">
            <h3>성공/실패</h3>
            <p><?= number_format((int)$summary['success_count']) ?> / <?= number_format((int)$summary['fail_count']) ?></p>
        </article>
        <article class="loginlog-card stat">
            <h3>관리자/IP</h3>
            <p><?= number_format((int)$summary['admin_count']) ?>명 / <?= number_format((int)$summary['ip_count']) ?>개</p>
        </article>
    </section>

    <section class="loginlog-card table-wrap">
        <div class="table-head table-head-tabs">
            <h2>로그인 로그 목록</h2>
            <div class="table-head-right">
                <div class="loginlog-tabs js-loginlog-tabs" role="tablist" aria-label="로그인 로그 조회 탭">
                    <button type="button" class="loginlog-tab is-active js-loginlog-tab" data-tab-target="log-list" aria-selected="true">로그인 로그 목록</button>
                    <button type="button" class="loginlog-tab js-loginlog-tab" data-tab-target="timeline" aria-selected="false">관리자 타임라인</button>
                </div>
                <p>페이지 <?= $currentPage ?> / <?= $totalPages ?></p>
            </div>
        </div>

        <div class="loginlog-tab-panel is-active" data-tab-panel="log-list">
            <div class="table-scroll">
                <table>
                    <thead>
                    <tr>
                        <th>로그인시각</th>
                        <th>관리자</th>
                        <th>권한</th>
                        <th>상태</th>
                        <th>IP</th>
                        <th>기기</th>
                        <th>브라우저/OS</th>
                        <th>위치</th>
                        <th>위치보기</th>
                        <th>요청 URI</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php if (count($rows) === 0): ?>
                        <tr>
                            <td colspan="10" class="empty">조회 결과가 없습니다.</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($rows as $row): ?>
                            <?php
                            $status = strtoupper((string)($row['cashhome_1300_login_status'] ?? ''));
                            $statusClass = ($status === 'SUCCESS') ? 'status-success' : 'status-fail';
                            $locationText = build_location_text($row);

                            $latitudeRaw = trim((string)($row['cashhome_1300_latitude'] ?? ''));
                            $longitudeRaw = trim((string)($row['cashhome_1300_longitude'] ?? ''));
                            $hasCoordinates = ($latitudeRaw !== '' && $longitudeRaw !== '' && is_numeric($latitudeRaw) && is_numeric($longitudeRaw));

                            $mapLocationValue = ($locationText === '-') ? '' : $locationText;
                            if ($mapLocationValue !== '' && filter_var($mapLocationValue, FILTER_VALIDATE_IP) !== false) {
                                $mapLocationValue = '';
                            }

                            $mapIpValue = trim((string)($row['cashhome_1300_login_ip'] ?? ''));
                            if ($mapIpValue === '-') {
                                $mapIpValue = '';
                            }

                            $hasMapSource = $hasCoordinates || $mapLocationValue !== '' || $mapIpValue !== '';
                            $mapAdminLabel = trim((string)($row['cashhome_1300_admin_username'] ?? ''));
                            if ($mapAdminLabel === '') {
                                $mapAdminLabel = admin_label_from_id((int)($row['cashhome_1300_admin_db_id'] ?? 0));
                            }

                            $mapFallbackQuery = '';
                            if ($hasCoordinates) {
                                $mapFallbackQuery = $latitudeRaw . ',' . $longitudeRaw;
                            } elseif ($mapLocationValue !== '') {
                                $mapFallbackQuery = $mapLocationValue;
                            }
                            $mapFallbackUrl = 'https://www.google.com/maps?q=' . rawurlencode($mapFallbackQuery === '' ? '로그인 위치' : $mapFallbackQuery);
                            ?>
                            <tr>
                                <td><?= h((string)($row['cashhome_1300_login_at'] ?? '-')) ?></td>
                                <td>
                                    <div class="user-main"><?= h((string)($row['cashhome_1300_admin_username'] ?? '-')) ?></div>
                                    <div class="user-sub">#<?= h((string)($row['cashhome_1300_admin_db_id'] ?? '0')) ?></div>
                                </td>
                                <td><?= h((string)($row['cashhome_1300_admin_role'] ?? '-')) ?></td>
                                <td><span class="status <?= h($statusClass) ?>"><?= h($status !== '' ? $status : '-') ?></span></td>
                                <td><?= h((string)($row['cashhome_1300_login_ip'] ?? '-')) ?></td>
                                <td><?= h((string)($row['cashhome_1300_device_type'] ?? '-')) ?></td>
                                <td><?= h(trim((string)($row['cashhome_1300_browser'] ?? '-')) . ' / ' . trim((string)($row['cashhome_1300_os_name'] ?? '-'))) ?></td>
                                <td><?= h($locationText) ?></td>
                                <td>
                                    <?php if ($hasMapSource): ?>
                                        <a
                                            href="<?= h($mapFallbackUrl) ?>"
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            class="btn map-view-btn js-map-open"
                                            data-lat="<?= h($hasCoordinates ? $latitudeRaw : '') ?>"
                                            data-lng="<?= h($hasCoordinates ? $longitudeRaw : '') ?>"
                                            data-location="<?= h($mapLocationValue) ?>"
                                            data-ip="<?= h($mapIpValue) ?>"
                                            data-user="<?= h($mapAdminLabel) ?>"
                                            data-login-at="<?= h((string)($row['cashhome_1300_login_at'] ?? '-')) ?>"
                                        >위치보기</a>
                                    <?php else: ?>
                                        <span class="map-na">-</span>
                                    <?php endif; ?>
                                </td>
                                <td><?= h((string)($row['cashhome_1300_request_uri'] ?? '-')) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <div class="table-pagination">
                <a class="btn" href="<?= h($prevUrl) ?>" <?= $currentPage <= 1 ? 'aria-disabled="true"' : '' ?>>이전</a>
                <span><?= $currentPage ?> / <?= $totalPages ?></span>
                <a class="btn" href="<?= h($nextUrl) ?>" <?= $currentPage >= $totalPages ? 'aria-disabled="true"' : '' ?>>다음</a>
            </div>
        </div>

        <div class="loginlog-tab-panel" data-tab-panel="timeline">
            <div class="timeline-toolbar">
                <label class="timeline-user-field">
                    <span>관리자 목록</span>
                    <select class="js-loginlog-timeline-user-select">
                        <?php if (count($timelineAdmins) === 0): ?>
                            <option value="0">조회 기간 관리자 없음</option>
                        <?php else: ?>
                            <?php foreach ($timelineAdmins as $adminItem): ?>
                                <?php
                                $aid = (int)($adminItem['cashhome_1300_admin_db_id'] ?? 0);
                                $aname = trim((string)($adminItem['admin_username'] ?? ''));
                                if ($aname === '') {
                                    $aname = admin_label_from_id($aid);
                                }
                                $arole = strtoupper(trim((string)($adminItem['admin_role'] ?? 'ADMIN')));
                                $acount = (int)($adminItem['login_count'] ?? 0);
                                ?>
                                <option value="<?= $aid ?>" <?= $aid === $selectedTimelineAdminId ? 'selected' : '' ?>>
                                    <?= h($aname) ?> (#<?= $aid ?>) / <?= h($arole) ?> / <?= number_format($acount) ?>회
                                </option>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </select>
                </label>
                <button type="button" class="btn primary js-loginlog-timeline-load">타임라인 보기</button>
            </div>

            <div class="timeline-userlist-scroll">
                <table class="timeline-userlist-table">
                    <thead>
                    <tr>
                        <th>관리자</th>
                        <th>권한</th>
                        <th>로그인</th>
                        <th>좌표</th>
                        <th>최근시각</th>
                        <th>선택</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php if (count($timelineAdmins) === 0): ?>
                        <tr>
                            <td colspan="6" class="empty">조회 기간에 타임라인 관리자가 없습니다.</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($timelineAdmins as $adminItem): ?>
                            <?php
                            $aid = (int)($adminItem['cashhome_1300_admin_db_id'] ?? 0);
                            $aname = trim((string)($adminItem['admin_username'] ?? ''));
                            if ($aname === '') {
                                $aname = admin_label_from_id($aid);
                            }
                            $arole = strtoupper(trim((string)($adminItem['admin_role'] ?? 'ADMIN')));
                            $acount = (int)($adminItem['login_count'] ?? 0);
                            $coordCount = (int)($adminItem['coordinate_count'] ?? 0);
                            ?>
                            <tr class="<?= $aid === $selectedTimelineAdminId ? 'is-selected' : '' ?>">
                                <td>
                                    <div class="user-main"><?= h($aname) ?></div>
                                    <div class="user-sub">#<?= $aid ?></div>
                                </td>
                                <td><?= h($arole) ?></td>
                                <td><?= number_format($acount) ?>회</td>
                                <td><?= number_format($coordCount) ?>건</td>
                                <td><?= h((string)($adminItem['last_login_at'] ?? '-')) ?></td>
                                <td>
                                    <button
                                        type="button"
                                        class="btn timeline-user-pick js-loginlog-timeline-user-pick"
                                        data-user-id="<?= $aid ?>"
                                    >선택</button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <div
                class="timeline-map-wrap js-loginlog-timeline"
                data-endpoint="<?= h($timelineApiUrl) ?>"
                data-selected-user-id="<?= (int)$selectedTimelineAdminId ?>"
                data-date-from="<?= h((string)$filters['date_from']) ?>"
                data-date-to="<?= h((string)$filters['date_to']) ?>"
            >
                <div class="timeline-map js-loginlog-timeline-map"></div>
                <aside class="timeline-side">
                    <h3>로그인 시간대 타임라인</h3>
                    <p class="timeline-meta js-loginlog-timeline-meta">관리자를 선택하고 [타임라인 보기]를 누르면 조회 기간의 로그인 순서가 표시됩니다.</p>
                    <ol class="timeline-point-list js-loginlog-timeline-list">
                        <li class="empty">표시할 타임라인이 없습니다.</li>
                    </ol>
                </aside>
            </div>
        </div>
    </section>

    <div class="loginlog-map-modal js-loginlog-map-modal" hidden>
        <div class="loginlog-map-dialog" role="dialog" aria-modal="true" aria-label="로그인 위치 지도">
            <div class="loginlog-map-head">
                <h3>로그인 위치</h3>
                <button type="button" class="btn map-close js-map-close">닫기</button>
            </div>
            <p class="loginlog-map-meta js-map-meta">선택한 로그인 위치 정보가 여기에 표시됩니다.</p>
            <div class="loginlog-map-frame-wrap">
                <iframe
                    class="loginlog-map-frame js-map-frame"
                    title="로그인 위치 지도"
                    loading="lazy"
                    referrerpolicy="no-referrer-when-downgrade"
                ></iframe>
            </div>
            <div class="loginlog-map-actions">
                <a class="btn js-map-google" href="#" target="_blank" rel="noopener noreferrer">구글 지도</a>
                <a class="btn js-map-kakao" href="#" target="_blank" rel="noopener noreferrer">카카오맵</a>
            </div>
        </div>
    </div>
</div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>
<script>
(function () {
  function setupFilterAutoSubmit() {
    var form = document.querySelector('.js-loginlog-filter');
    if (!form) {
      return;
    }

    var pageInput = form.querySelector('.js-page-input');
    var autoFields = form.querySelectorAll('input[type="date"], select[name="status"], select[name="admin_role"], select[name="per_page"]');
    var textInputs = form.querySelectorAll('input[name="keyword"], input[name="ip_keyword"]');
    var timer = null;

    function submitWithResetPage() {
      if (pageInput) {
        pageInput.value = '1';
      }
      form.submit();
    }

    function debounceSubmit() {
      if (timer) {
        clearTimeout(timer);
      }
      timer = setTimeout(function () {
        submitWithResetPage();
      }, 220);
    }

    for (var i = 0; i < autoFields.length; i += 1) {
      autoFields[i].addEventListener('change', debounceSubmit);
    }

    for (var j = 0; j < textInputs.length; j += 1) {
      textInputs[j].addEventListener('keydown', function (event) {
        if (event.key === 'Enter') {
          event.preventDefault();
          submitWithResetPage();
        }
      });
    }
  }

  function setupTabs() {
    var tabRoot = document.querySelector('.js-loginlog-tabs');
    if (!tabRoot) {
      return;
    }

    var wrapper = tabRoot.closest('.table-wrap');
    if (!wrapper) {
      return;
    }

    var tabs = tabRoot.querySelectorAll('.js-loginlog-tab');
    var panels = wrapper.querySelectorAll('.loginlog-tab-panel');

    function activateTab(tab) {
      var target = tab.getAttribute('data-tab-target') || '';

      for (var i = 0; i < tabs.length; i += 1) {
        var isActive = tabs[i] === tab;
        tabs[i].classList.toggle('is-active', isActive);
        tabs[i].setAttribute('aria-selected', isActive ? 'true' : 'false');
      }

      for (var j = 0; j < panels.length; j += 1) {
        var panel = panels[j];
        var panelKey = panel.getAttribute('data-tab-panel') || '';
        panel.classList.toggle('is-active', panelKey === target);
      }

      if (target === 'timeline') {
        document.dispatchEvent(new CustomEvent('loginlog:timeline-tab-shown'));
      }
    }

    for (var k = 0; k < tabs.length; k += 1) {
      tabs[k].addEventListener('click', function () {
        activateTab(this);
      });
    }
  }

  function setupTimeline() {
    var root = document.querySelector('.js-loginlog-timeline');
    if (!root) {
      return;
    }

    var userSelect = document.querySelector('.js-loginlog-timeline-user-select');
    var loadButton = document.querySelector('.js-loginlog-timeline-load');
    var userPickButtons = document.querySelectorAll('.js-loginlog-timeline-user-pick');
    var mapEl = root.querySelector('.js-loginlog-timeline-map');
    var metaEl = root.querySelector('.js-loginlog-timeline-meta');
    var listEl = root.querySelector('.js-loginlog-timeline-list');

    var endpoint = root.getAttribute('data-endpoint') || '';
    var dateFrom = root.getAttribute('data-date-from') || '';
    var dateTo = root.getAttribute('data-date-to') || '';
    var selectedUserId = parseInt(root.getAttribute('data-selected-user-id') || '0', 10);
    if (isNaN(selectedUserId)) {
      selectedUserId = 0;
    }

    var map = null;
    var renderLayer = null;
    var markerBySeq = {};
    var requestToken = 0;
    var loadedOnce = false;

    if (userSelect && selectedUserId > 0) {
      userSelect.value = String(selectedUserId);
    }

    function escapeHtml(value) {
      return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function setMeta(text) {
      if (metaEl) {
        metaEl.textContent = text;
      }
    }

    function updateSelectedRows() {
      if (!userSelect) {
        return;
      }

      var currentId = userSelect.value;
      for (var i = 0; i < userPickButtons.length; i += 1) {
        var button = userPickButtons[i];
        var row = button.closest('tr');
        if (!row) {
          continue;
        }
        var rowId = button.getAttribute('data-user-id') || '';
        row.classList.toggle('is-selected', rowId === currentId);
      }
    }

    function ensureMap() {
      if (!mapEl) {
        return null;
      }

      if (typeof window.L === 'undefined') {
        mapEl.innerHTML = '<div class="timeline-map-empty">지도를 불러오지 못했습니다. 네트워크 상태를 확인하세요.</div>';
        return null;
      }

      if (!map) {
        map = window.L.map(mapEl, {
          zoomControl: true,
          attributionControl: true
        }).setView([37.5665, 126.9780], 11);

        window.L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
          maxZoom: 19,
          attribution: '&copy; OpenStreetMap contributors'
        }).addTo(map);

        renderLayer = window.L.layerGroup().addTo(map);
      }

      return map;
    }

    function clearMap() {
      markerBySeq = {};
      if (renderLayer) {
        renderLayer.clearLayers();
      }
    }

    function jumpToSeq(seq) {
      if (!map) {
        return;
      }
      var marker = markerBySeq[seq];
      if (!marker) {
        return;
      }

      var target = marker.getLatLng();
      var zoomLevel = map.getZoom();
      if (typeof zoomLevel !== 'number' || isNaN(zoomLevel)) {
        zoomLevel = 16;
      }
      if (zoomLevel < 16) {
        zoomLevel = 16;
      }

      function forceCenter() {
        if (!map) {
          return;
        }
        map.stop();
        map.setView(target, zoomLevel, { animate: false });
      }

      forceCenter();
      marker.openPopup();

      if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(forceCenter);
      }
      setTimeout(forceCenter, 60);
      setTimeout(forceCenter, 180);
    }

    function bindListClicks() {
      if (!listEl) {
        return;
      }

      listEl.addEventListener('click', function (event) {
        var target = event.target;
        if (!target || !target.classList || !target.classList.contains('js-timeline-jump')) {
          return;
        }

        event.preventDefault();
        var seq = parseInt(target.getAttribute('data-seq') || '0', 10);
        if (isNaN(seq) || seq <= 0) {
          return;
        }
        jumpToSeq(seq);
      });
    }

    function renderList(points, hasCoords) {
      if (!listEl) {
        return;
      }

      if (!points || points.length === 0) {
        listEl.innerHTML = '<li class="empty">조회 기간 로그인 이력이 없습니다.</li>';
        return;
      }

      var html = '';
      for (var i = 0; i < points.length; i += 1) {
        var point = points[i] || {};
        var seq = point.seq || (i + 1);
        var loginAt = point.login_at || '-';
        var locationText = point.location_text || '-';
        var ipText = point.login_ip || '-';
        var deviceText = point.device_type || '-';
        var hasCoordinates = !!point.has_coordinates;

        html += '<li class="timeline-point-item' + (hasCoordinates ? ' has-coord' : '') + '">';
        html += '<div class="timeline-point-head">';
        html += '<strong>#' + seq + '</strong>';
        html += '<span>' + escapeHtml(loginAt) + '</span>';
        if (hasCoordinates && hasCoords) {
          html += '<button type="button" class="btn timeline-jump js-timeline-jump" data-seq="' + seq + '">지도 이동</button>';
        }
        html += '</div>';
        html += '<div class="timeline-point-body">';
        html += '<div>' + escapeHtml(locationText) + '</div>';
        html += '<div class="timeline-point-sub">IP: ' + escapeHtml(ipText) + ' / 기기: ' + escapeHtml(deviceText) + '</div>';
        if (hasCoordinates) {
          html += '<div class="timeline-point-sub">좌표: ' + escapeHtml(String(point.latitude)) + ', ' + escapeHtml(String(point.longitude)) + '</div>';
        } else {
          html += '<div class="timeline-point-sub">좌표 없음</div>';
        }
        html += '</div>';
        html += '</li>';
      }

      listEl.innerHTML = html;
    }

    function renderMap(points, userLabel) {
      clearMap();

      if (!points || points.length === 0) {
        renderList([], false);
        setMeta('조회 기간 로그인 이력이 없습니다.');
        return;
      }

      var geoPoints = [];
      for (var i = 0; i < points.length; i += 1) {
        var point = points[i] || {};
        if (!point.has_coordinates) {
          continue;
        }
        if (typeof point.latitude !== 'number' || typeof point.longitude !== 'number') {
          continue;
        }
        geoPoints.push(point);
      }

      renderList(points, geoPoints.length > 0);

      if (geoPoints.length === 0) {
        setMeta((userLabel ? userLabel + ' / ' : '') + '좌표 데이터가 없어 지도를 그릴 수 없습니다.');
        return;
      }

      var activeMap = ensureMap();
      if (!activeMap || !renderLayer) {
        setMeta((userLabel ? userLabel + ' / ' : '') + '지도 라이브러리를 사용할 수 없습니다.');
        return;
      }

      var latLngs = [];

      function toDateWeekTimeLabel(loginAtText) {
        var raw = String(loginAtText || '').trim();
        if (raw === '') {
          return '-';
        }

        var weekdays = ['일', '월', '화', '수', '목', '금', '토'];
        var m = raw.match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})/);
        if (m) {
          var year = parseInt(m[1], 10);
          var month = parseInt(m[2], 10);
          var day = parseInt(m[3], 10);
          var hhText = m[4];
          var mmText = m[5];
          var d = new Date(year, month - 1, day);
          var w = isNaN(d.getTime()) ? '' : weekdays[d.getDay()];
          return m[2] + '.' + m[3] + '(' + w + ') ' + hhText + ':' + mmText;
        }

        var parsed = new Date(raw.replace(' ', 'T'));
        if (isNaN(parsed.getTime())) {
          return raw;
        }

        var mm = String(parsed.getMonth() + 1).padStart(2, '0');
        var dd = String(parsed.getDate()).padStart(2, '0');
        var hh = String(parsed.getHours()).padStart(2, '0');
        var mi = String(parsed.getMinutes()).padStart(2, '0');
        var wd = weekdays[parsed.getDay()];
        return mm + '.' + dd + '(' + wd + ') ' + hh + ':' + mi;
      }

      for (var j = 0; j < geoPoints.length; j += 1) {
        var geoPoint = geoPoints[j];
        var latLng = [geoPoint.latitude, geoPoint.longitude];
        latLngs.push(latLng);
        var timeLabel = toDateWeekTimeLabel(geoPoint.login_at || '');

        var popupHtml = '';
        popupHtml += '<div><strong>#' + geoPoint.seq + ' ' + escapeHtml(geoPoint.login_at || '-') + '</strong></div>';
        popupHtml += '<div>' + escapeHtml(geoPoint.location_text || '-') + '</div>';
        popupHtml += '<div>IP: ' + escapeHtml(geoPoint.login_ip || '-') + '</div>';

        var marker = window.L.marker(latLng, {
          title: '#' + geoPoint.seq + ' ' + (geoPoint.login_at || '')
        }).bindPopup(popupHtml, {
          autoPan: false,
          keepInView: false
        });

        if (timeLabel !== '-') {
          marker.bindTooltip(escapeHtml(timeLabel), {
            permanent: true,
            direction: 'top',
            offset: [0, -14],
            className: 'timeline-time-label'
          });
        }

        marker.addTo(renderLayer);
        markerBySeq[geoPoint.seq] = marker;
      }

      if (latLngs.length >= 2) {
        window.L.polyline(latLngs, {
          color: '#4cc3ff',
          weight: 3,
          opacity: 0.9
        }).addTo(renderLayer);
      }

      if (latLngs.length === 1) {
        activeMap.setView(latLngs[0], 15, { animate: true });
      } else {
        activeMap.fitBounds(window.L.latLngBounds(latLngs), {
          padding: [24, 24]
        });
      }

      setTimeout(function () {
        if (map) {
          map.invalidateSize();
        }
      }, 120);

      var message = (userLabel ? userLabel + ' / ' : '');
      message += dateFrom + ' ~ ' + dateTo + ' / 총 ' + points.length + '건 / 좌표 ' + geoPoints.length + '건';
      setMeta(message);
    }

    function fetchTimeline() {
      if (!userSelect) {
        return;
      }

      var userId = parseInt(userSelect.value || '0', 10);
      if (isNaN(userId) || userId <= 0) {
        renderList([], false);
        clearMap();
        setMeta('관리자를 선택해주세요.');
        return;
      }

      if (!endpoint) {
        setMeta('타임라인 API 주소가 없습니다.');
        return;
      }

      selectedUserId = userId;
      root.setAttribute('data-selected-user-id', String(userId));
      updateSelectedRows();

      var url = endpoint + '&timeline_admin_id=' + encodeURIComponent(String(userId));
      var currentToken = requestToken + 1;
      requestToken = currentToken;

      if (loadButton) {
        loadButton.disabled = true;
      }

      setMeta('타임라인 데이터를 조회중입니다...');

      fetch(url, {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
          Accept: 'application/json'
        }
      })
        .then(function (response) {
          if (!response.ok) {
            throw new Error('HTTP ' + response.status);
          }
          return response.json();
        })
        .then(function (payload) {
          if (currentToken !== requestToken) {
            return;
          }

          if (!payload || payload.ok !== true) {
            var message = (payload && payload.message) ? payload.message : '타임라인 조회에 실패했습니다.';
            renderList([], false);
            clearMap();
            setMeta(message);
            return;
          }

          var points = Array.isArray(payload.points) ? payload.points : [];
          var adminInfo = payload.admin && typeof payload.admin === 'object' ? payload.admin : {};
          var userLabel = adminInfo.admin_name || ('관리자#' + userId);
          renderMap(points, userLabel);
          loadedOnce = true;
        })
        .catch(function () {
          if (currentToken !== requestToken) {
            return;
          }
          renderList([], false);
          clearMap();
          setMeta('타임라인 조회 중 오류가 발생했습니다.');
        })
        .finally(function () {
          if (currentToken !== requestToken) {
            return;
          }
          if (loadButton) {
            loadButton.disabled = false;
          }
        });
    }

    if (userSelect) {
      userSelect.addEventListener('change', function () {
        updateSelectedRows();
        fetchTimeline();
      });
    }

    if (loadButton) {
      loadButton.addEventListener('click', function () {
        fetchTimeline();
      });
    }

    for (var i = 0; i < userPickButtons.length; i += 1) {
      userPickButtons[i].addEventListener('click', function () {
        var uid = this.getAttribute('data-user-id') || '0';
        if (userSelect) {
          userSelect.value = uid;
        }
        updateSelectedRows();
        fetchTimeline();
      });
    }

    document.addEventListener('loginlog:timeline-tab-shown', function () {
      if (map) {
        setTimeout(function () {
          map.invalidateSize();
        }, 120);
      }
      if (!loadedOnce && userSelect && parseInt(userSelect.value || '0', 10) > 0) {
        fetchTimeline();
      }
    });

    bindListClicks();
    updateSelectedRows();
  }

  function setupLocationModal() {
    var modal = document.querySelector('.js-loginlog-map-modal');
    if (!modal) {
      return;
    }

    // Always start closed. CSS override on [hidden] is explicitly handled.
    modal.hidden = true;
    document.body.classList.remove('loginlog-modal-open');

    if (modal.parentNode !== document.body) {
      document.body.appendChild(modal);
    }

    var closeBtn = modal.querySelector('.js-map-close');
    var mapFrame = modal.querySelector('.js-map-frame');
    var mapMeta = modal.querySelector('.js-map-meta');
    var googleLink = modal.querySelector('.js-map-google');
    var kakaoLink = modal.querySelector('.js-map-kakao');
    var openToken = 0;
    var lastTapTime = 0;
    var lastTapKey = '';

    function buildUrls(latValue, lngValue, locationText) {
      var hasLat = latValue !== '' && !isNaN(parseFloat(latValue));
      var hasLng = lngValue !== '' && !isNaN(parseFloat(lngValue));
      var hasCoords = hasLat && hasLng;
      var label = locationText || '';

      if (!hasCoords && label === '') {
        return null;
      }

      var query = hasCoords ? (latValue + ',' + lngValue) : label;
      var encodedQuery = encodeURIComponent(query);

      var googleUrl = 'https://www.google.com/maps?q=' + encodedQuery;
      var embedUrl = googleUrl + '&output=embed';
      var kakaoUrl = hasCoords
        ? ('https://map.kakao.com/link/map/' + encodeURIComponent('로그인위치') + ',' + latValue + ',' + lngValue)
        : ('https://map.kakao.com/?q=' + encodeURIComponent(label));

      return {
        embedUrl: embedUrl,
        googleUrl: googleUrl,
        kakaoUrl: kakaoUrl
      };
    }

    function isIpLiteral(value) {
      if (!value) {
        return false;
      }

      var text = String(value).trim();
      if (text === '') {
        return false;
      }

      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) {
        return true;
      }

      if (/^[0-9a-fA-F:]+$/.test(text) && text.indexOf(':') !== -1) {
        return true;
      }

      return false;
    }

    function isPrivateIp(ipValue) {
      if (!ipValue) {
        return true;
      }

      var ip = ipValue.toLowerCase();
      if (ip === '::1' || ip === 'localhost' || ip.indexOf('fe80:') === 0 || ip.indexOf('fc') === 0 || ip.indexOf('fd') === 0) {
        return true;
      }

      if (/^127\./.test(ip) || /^10\./.test(ip) || /^192\.168\./.test(ip)) {
        return true;
      }

      var match172 = ip.match(/^172\.(\d{1,3})\./);
      if (match172) {
        var second = parseInt(match172[1], 10);
        if (!isNaN(second) && second >= 16 && second <= 31) {
          return true;
        }
      }

      return false;
    }

    function resolveByIp(ipValue) {
      if (!ipValue || isPrivateIp(ipValue) || typeof fetch !== 'function') {
        return Promise.resolve(null);
      }

      var endpoint = 'https://ipapi.co/' + encodeURIComponent(ipValue) + '/json/';
      return fetch(endpoint, { method: 'GET' })
        .then(function (response) {
          if (!response || !response.ok) {
            return null;
          }
          return response.json();
        })
        .then(function (data) {
          if (!data || typeof data !== 'object') {
            return null;
          }

          var lat = data.latitude;
          var lng = data.longitude;
          if (lat === undefined || lat === null || lng === undefined || lng === null) {
            return null;
          }

          var latText = String(lat).trim();
          var lngText = String(lng).trim();
          if (latText === '' || lngText === '' || isNaN(parseFloat(latText)) || isNaN(parseFloat(lngText))) {
            return null;
          }

          var locationParts = [];
          if (data.city) {
            locationParts.push(String(data.city));
          }
          if (data.region) {
            locationParts.push(String(data.region));
          }
          if (data.country_name) {
            locationParts.push(String(data.country_name));
          }

          return {
            lat: latText,
            lng: lngText,
            location: locationParts.join(', ')
          };
        })
        .catch(function () {
          return null;
        });
    }

    function setMapUrls(urls) {
      if (!urls) {
        if (mapFrame) {
          mapFrame.removeAttribute('src');
        }
        if (googleLink) {
          googleLink.removeAttribute('href');
        }
        if (kakaoLink) {
          kakaoLink.removeAttribute('href');
        }
        return;
      }

      if (mapFrame) {
        mapFrame.setAttribute('src', urls.embedUrl);
      }

      if (googleLink) {
        googleLink.setAttribute('href', urls.googleUrl);
      }

      if (kakaoLink) {
        kakaoLink.setAttribute('href', urls.kakaoUrl);
      }
    }

    function baseMetaText(userText, loginAtText) {
      var text = '';
      if (userText !== '') {
        text += userText;
      }
      if (loginAtText !== '') {
        text += (text === '' ? '' : ' / ') + loginAtText;
      }
      return text;
    }

    function closeModal() {
      openToken += 1;
      modal.hidden = true;
      document.body.classList.remove('loginlog-modal-open');
      if (mapFrame) {
        mapFrame.removeAttribute('src');
      }
    }

    function openModal(button) {
      openToken += 1;
      var currentToken = openToken;

      var latValue = (button.getAttribute('data-lat') || '').trim();
      var lngValue = (button.getAttribute('data-lng') || '').trim();
      var locationTextRaw = (button.getAttribute('data-location') || '').trim();
      var locationText = isIpLiteral(locationTextRaw) ? '' : locationTextRaw;
      var ipValue = (button.getAttribute('data-ip') || '').trim();
      var userText = (button.getAttribute('data-user') || '').trim();
      var loginAtText = (button.getAttribute('data-login-at') || '').trim();

      var headerMeta = baseMetaText(userText, loginAtText);
      var directUrls = buildUrls(latValue, lngValue, locationText);

      modal.hidden = false;
      document.body.classList.add('loginlog-modal-open');

      if (directUrls) {
        setMapUrls(directUrls);
        if (mapMeta) {
          var directMeta = headerMeta;
          var locText = locationText !== '' ? locationText : (latValue + ', ' + lngValue);
          directMeta += (directMeta === '' ? '' : ' / ') + locText;
          mapMeta.textContent = directMeta === '' ? '로그인 위치 정보' : directMeta;
        }
        return;
      }

      if (ipValue === '') {
        setMapUrls(null);
        if (mapMeta) {
          mapMeta.textContent = (headerMeta === '' ? '' : (headerMeta + ' / ')) + '위치 데이터가 없습니다.';
        }
        return;
      }

      setMapUrls(null);
      if (mapMeta) {
        mapMeta.textContent = (headerMeta === '' ? '' : (headerMeta + ' / ')) + ('IP(' + ipValue + ') 기반 위치 조회중...');
      }

      resolveByIp(ipValue).then(function (resolved) {
        if (currentToken !== openToken || modal.hidden) {
          return;
        }

        if (!resolved) {
          if (mapMeta) {
            mapMeta.textContent = (headerMeta === '' ? '' : (headerMeta + ' / ')) + ('IP(' + ipValue + ')의 위치를 확인하지 못했습니다.');
          }
          return;
        }

        var resolvedLabel = resolved.location || ipValue;
        var resolvedUrls = buildUrls(resolved.lat, resolved.lng, resolvedLabel);
        setMapUrls(resolvedUrls);

        if (mapMeta) {
          var resolvedMeta = headerMeta;
          resolvedMeta += (resolvedMeta === '' ? '' : ' / ') + resolvedLabel;
          resolvedMeta += ' / ' + resolved.lat + ', ' + resolved.lng;
          mapMeta.textContent = resolvedMeta;
        }
      });
    }

    function extractMapButton(target) {
      var node = target;
      while (node && node !== document) {
        if (node.nodeType === 1 && node.classList && node.classList.contains('js-map-open')) {
          return node;
        }
        node = node.parentNode;
      }
      return null;
    }

    function openModalSafe(button) {
      var key = [
        button.getAttribute('data-user') || '',
        button.getAttribute('data-login-at') || '',
        button.getAttribute('data-lat') || '',
        button.getAttribute('data-lng') || '',
        button.getAttribute('data-ip') || ''
      ].join('|');
      var now = Date.now();
      if (key === lastTapKey && (now - lastTapTime) < 500) {
        return;
      }
      lastTapKey = key;
      lastTapTime = now;
      openModal(button);
    }

    function getElementTarget(target) {
      if (!target) {
        return null;
      }
      if (target.nodeType === 1) {
        return target;
      }
      if (target.parentElement && target.parentElement.nodeType === 1) {
        return target.parentElement;
      }
      return null;
    }

    var mapButtons = document.querySelectorAll('.js-map-open');
    for (var k = 0; k < mapButtons.length; k += 1) {
      mapButtons[k].addEventListener('click', function (event) {
        event.preventDefault();
        openModalSafe(this);
      });
      mapButtons[k].addEventListener('touchend', function (event) {
        if (event && event.cancelable) {
          event.preventDefault();
        }
        openModalSafe(this);
      });
    }

    document.addEventListener('click', function (event) {
      var btn = extractMapButton(event.target);
      if (!btn) {
        return;
      }
      event.preventDefault();
      openModalSafe(btn);
    }, true);

    document.addEventListener('touchend', function (event) {
      var btn = extractMapButton(event.target);
      if (!btn) {
        return;
      }
      if (event && event.cancelable) {
        event.preventDefault();
      }
      openModalSafe(btn);
    }, true);

    modal.addEventListener('click', function (event) {
      var targetEl = getElementTarget(event.target);
      if (targetEl === modal) {
        closeModal();
      }
    });

    if (closeBtn) {
      closeBtn.addEventListener('click', function () {
        closeModal();
      });
    }

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && !modal.hidden) {
        closeModal();
      }
    });
  }

  setupFilterAutoSubmit();
  setupTabs();
  setupTimeline();
  setupLocationModal();
})();
</script>
</body>
</html>
