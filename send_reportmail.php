<?php

require_once __DIR__ . '/vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

require_once __DIR__ . '/mail_sender.php';

const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

const OC_PENDING   = '1'; // 대기
const OC_REVIEWING = '2'; // 검토중
const OC_APPROVED  = '3'; // 승인
const OC_PAID      = '4'; // 출금완료
const OC_REJECTED  = '5'; // 부결

// status codes
const ST_NEW          = 'new';
const ST_CONTACTED    = 'contacted';
const ST_PROGRESSING  = 'progressing';
const ST_CLOSED_OK    = 'closed_ok';
const ST_CLOSED_ISSUE = 'closed_issue';

// closed 상태 판별용
const CLOSED_STATUSES = [ST_CLOSED_OK, ST_CLOSED_ISSUE];

// 메일 수신자
const REPORT_MAIL_TO = 'ecashhome@gmail.com';

function cashhome_pdo(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;

    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
    return $pdo;
}

function send_report_mail(PDO $pdo): bool
{
    [$subject, $html, $plain] = build_report_mail_body($pdo);

    try {
        $ms = new MailSender();
        return $ms->sendHtmlTo(REPORT_MAIL_TO, $subject, $html, $plain);
    } catch (Throwable $e) {
        error_log('[report_mail] ' . $e->getMessage());
        return false;
    }
}

/**
 * ✅ CLI 모드로 리포트 전송 (웹 접근 차단)
 */
if (PHP_SAPI === 'cli') {
    global $argv;
    if (isset($argv[1]) && $argv[1] === '--send-report') {
        $pdoCli = cashhome_pdo();
        $ok = send_report_mail($pdoCli);
        echo $ok ? "OK\n" : "FAIL\n";
        exit;
    }
}

function fetch_rows_for_period(PDO $pdo, string $startDT, string $endDT): array
{
    $stmt = $pdo->prepare("
      SELECT
        cashhome_1000_id,
        cashhome_1000_loan_no,
        cashhome_1000_created_at,
        cashhome_1000_customer_name,
        cashhome_1000_customer_phone,
        cashhome_1000_loan_amount,
        cashhome_1000_status,
        cashhome_1000_outcome,
        cashhome_1000_doc_token_status,
        cashhome_1000_doc_token_expires_at
      FROM cashhome_1000_inquiries
      WHERE cashhome_1000_created_at BETWEEN :s AND :e
      ORDER BY cashhome_1000_id DESC
      LIMIT 20000
    ");
    $stmt->execute([':s' => $startDT, ':e' => $endDT]);
    $rows = $stmt->fetchAll();

    foreach ($rows as &$r) {
        $r['cashhome_1000_outcome'] = normalize_outcome_legacy((string)($r['cashhome_1000_outcome'] ?? OC_PENDING));
        $r['cashhome_1000_status']  = (string)($r['cashhome_1000_status'] ?? ST_NEW);
    }
    unset($r);

    return $rows;
}

function fmt_kr_date(string $ymd): string
{
    if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $ymd, $m)) return $ymd;
    $yy = substr($m[1], 2, 2);
    return sprintf('%s년 %s월 %s일', $yy, $m[2], $m[3]);
}

function normalize_outcome_legacy(string $s): string
{
    $s = trim($s);
    if ($s === '') return OC_PENDING;

    if (preg_match('/^[1-5]$/', $s)) return $s;

    return match ($s) {
        'pending'  => OC_PENDING,
        'approved' => OC_APPROVED,
        'rejected' => OC_REJECTED,
        default    => OC_PENDING,
    };
}

function group_by_outcome(array $rows): array
{
    $g = [];
    foreach ($rows as $r) {
        $k = (string)($r['cashhome_1000_outcome'] ?? OC_PENDING);
        $g[$k][] = $r;
    }
    return $g;
}

function group_by_status(array $rows): array
{
    $g = [];
    foreach ($rows as $r) {
        $k = (string)($r['cashhome_1000_status'] ?? ST_NEW);
        $g[$k][] = $r;
    }
    return $g;
}

function build_report_mail_body(PDO $pdo): array
{
    // 최근 3개월
    $end   = new DateTimeImmutable('now');
    $start = $end->sub(new DateInterval('P3M'));

    $startYmd = $start->format('Y-m-d');
    $endYmd   = $end->format('Y-m-d');

    $startDT = $startYmd . ' 00:00:00';
    $endDT   = $endYmd . ' 23:59:59';

    $rows = fetch_rows_for_period($pdo, $startDT, $endDT);
    $total = count($rows);

    // ✅ 원본에서 주석 때문에 깨지던 집계 복구
    $groupOutcome = group_by_outcome($rows);
    $groupStatusM = group_by_status($rows);

    $cntPending  = count($groupOutcome[OC_PENDING] ?? []);
    $cntRejected = count($groupOutcome[OC_REJECTED] ?? []);
    $cntApproved = count($groupOutcome[OC_APPROVED] ?? []);

    // token 만료(5시간 미만)
    $expiring = [];
    $nowTs = time();
    foreach ($rows as $r) {
        $status    = (int)($r['cashhome_1000_doc_token_status'] ?? 0); // 1=발급, 2=사용
        $expiresAt = (string)($r['cashhome_1000_doc_token_expires_at'] ?? '');
        if ($status !== 1 || $expiresAt === '') continue;

        $expTs = strtotime($expiresAt);
        if ($expTs === false) continue;

        $remainSec = $expTs - $nowTs;
        if ($remainSec <= 0) continue;

        if ($remainSec < 5 * 3600) {
            $r['_remain_hours'] = round($remainSec / 3600, 2);
            $expiring[] = $r;
        }
    }

    $subject = '[CASHHOME] 최근3개월 통계 리포트 (' . fmt_kr_date($startYmd) . ' ~ ' . fmt_kr_date($endYmd) . ')';

    $h = static function (string $s): string {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    };

    $fmtAmt = static function ($v): string {
        $n = (string)$v;
        $n = preg_replace('/[^\d]/', '', $n);
        if ($n === '') return '';
        return number_format((int)$n);
    };

    /**
     * ✅ 메일 표: 모든 리스트에서 id/대출번호 같은 값은 제거
     * ✅ 대신 순번(1,2,3...)만 출력
     */
    $renderTable = static function (array $rows) use ($h, $fmtAmt): string {
        if (!$rows) {
            return '<div style="color:#666;font-size:12px;">(없음)</div>';
        }

        $html = '<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%;font-size:13px;">';
        $html .= '<thead><tr style="background:#f2f2f2;">'
            . '<th align="center" width="60">순번</th>'
            . '<th align="left">신청자</th>'
            . '<th align="right">금액</th>'
            . '<th align="left">연락처</th>'
            . '</tr></thead><tbody>';

        $i = 1;
        foreach ($rows as $r) {
            $name  = $h((string)($r['cashhome_1000_customer_name'] ?? ''));
            $amt   = $h($fmtAmt($r['cashhome_1000_loan_amount'] ?? ''));
            $phone = $h((string)($r['cashhome_1000_customer_phone'] ?? ''));

            $html .= '<tr>'
                . '<td align="center">' . $i . '</td>'
                . '<td>' . $name . '</td>'
                . '<td align="right">' . $amt . '</td>'
                . '<td>' . $phone . '</td>'
                . '</tr>';

            $i++;
        }

        $html .= '</tbody></table>';
        return $html;
    };

    $html = '';
    $html .= '<div style="font-family:Apple SD Gothic Neo,Malgun Gothic,Arial,sans-serif;">';
    $html .= '<h2 style="margin:0 0 10px 0;">CASHHOME 통계 리포트</h2>';
    $html .= '<div style="margin:0 0 14px 0;color:#333;">(조회기간 표시 ' . $h(fmt_kr_date($startYmd)) . ' ~ ' . $h(fmt_kr_date($endYmd)) . ' 까지)</div>';

    // 요약
    $html .= '<h3 style="margin:18px 0 8px 0;">대출정보</h3>';
    $html .= '<ul style="margin:0 0 12px 18px;padding:0;">'
        . '<li>대출 총건수: <b>' . $total . '</b></li>'
        . '<li>대기 총건수: <b>' . $cntPending . '</b></li>'
        . '<li>부결 총건수: <b>' . $cntRejected . '</b></li>'
        . '<li>승인 총건수: <b>' . $cntApproved . '</b></li>'
        . '</ul>';

    // 토큰 만료
    $html .= '<h3 style="margin:18px 0 8px 0;">토큰 만료 요약</h3>';
    $html .= '<div style="margin:0 0 8px 0;">1. 토큰이 5시간 미만으로 남은 건수가 <b>' . count($expiring) . '</b>건(서류등록 독촉)</div>';
    $html .= $renderTable($expiring);

    // outcome 섹션
    $html .= '<h3 style="margin:22px 0 8px 0;">대출결과 요약</h3>';

    $mapOutcomeOrder = [
        OC_PENDING   => '1. 대출 대기건',
        OC_REVIEWING => '2. 대출 검토건',
        OC_APPROVED  => '3. 대출 승인',
        OC_PAID      => '4. 대출 출금완료',
        OC_REJECTED  => '5. 대출 부결',
    ];

    foreach ($mapOutcomeOrder as $k => $title) {
        $rows2 = $groupOutcome[$k] ?? [];
        $html .= '<h4 style="margin:14px 0 6px 0;">' . $h($title) . ' : <b>' . count($rows2) . '</b>건</h4>';
        $html .= $renderTable($rows2);
    }

    // status 섹션
    $html .= '<h3 style="margin:22px 0 8px 0;">처리상태 요약</h3>';
    $html .= '<div style="margin:0 0 10px 0;color:#333;">master=신규 / 연락완료 / 대출진행중 / 정상종결 / 문제종결</div>';

    $mapStatusOrder = [
        ST_NEW          => '1.대출 신규',
        ST_CONTACTED    => '2.대출 연락완료',
        ST_PROGRESSING  => '3.대출 진행',
        ST_CLOSED_OK    => '4.대출 정상종결',
        ST_CLOSED_ISSUE => '5.대출 문제종결',
    ];

    foreach ($mapStatusOrder as $k => $title) {
        $rows3 = $groupStatusM[$k] ?? [];
        $html .= '<h4 style="margin:14px 0 6px 0;">' . $h($title) . ' : <b>' . count($rows3) . '</b>건</h4>';
        $html .= $renderTable($rows3);
    }

    $html .= '<div style="margin-top:18px;color:#888;font-size:12px;">※ 본 메일은 3시간마다 자동 발송됩니다.</div>';
    $html .= '</div>';

    $plain = "(조회기간 표시 {$startYmd} ~ {$endYmd})\n"
        . "대출정보\n"
        . "1.대출 총건수: {$total}\n"
        . "2.대기 총건수: {$cntPending}\n"
        . "3.부결 총건수: {$cntRejected}\n"
        . "4.승인 총건수: {$cntApproved}\n";

    return [$subject, $html, $plain];
}

?>