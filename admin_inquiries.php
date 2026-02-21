<?php
declare(strict_types=1);

session_start();
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

// index.php와 동일 DB 설정
const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

// 로그인 유지 시간(초) - admin_login.php와 동일
const ADMIN_SESSION_TTL = 7200;

function cashhome_pdo(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;

    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}

function is_admin_authed(): bool {
    if (empty($_SESSION['cashhome_admin_authed']) || empty($_SESSION['cashhome_admin_authed_at'])) {
        return false;
    }
    if ((time() - (int)$_SESSION['cashhome_admin_authed_at']) > ADMIN_SESSION_TTL) {
        unset($_SESSION['cashhome_admin_authed'], $_SESSION['cashhome_admin_authed_at']);
        return false;
    }
    return true;
}

function consent_text(bool $ok): string {
    return $ok ? '동의함' : '미동의';
}

// 로그아웃
if (isset($_GET['logout']) && $_GET['logout'] === '1') {
    unset($_SESSION['cashhome_admin_authed'], $_SESSION['cashhome_admin_authed_at']);
    header('Location: admin_login.php');
    exit;
}

// 인증 체크
if (!is_admin_authed()) {
    header('Location: admin_login.php');
    exit;
}

// ---- 검색 파라미터(기간) ----
$today = date('Y-m-d');
$defaultStart = date('Y-m-d', strtotime('-7 days'));

$start = (string)($_GET['start'] ?? $defaultStart);
$end   = (string)($_GET['end'] ?? $today);

// 날짜 유효성(간단)
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $start)) $start = $defaultStart;
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $end))   $end   = $today;

// 종료일은 당일 23:59:59까지 포함
$startDT = $start . ' 00:00:00';
$endDT   = $end   . ' 23:59:59';

// 선택된 건
$selectedId = (int)($_GET['id'] ?? 0);

$rows = [];
$selected = null;
$error = '';
$notice = (string)($_GET['saved'] ?? '') === '1' ? '저장되었습니다.' : '';

try {
    $pdo = cashhome_pdo();

    // ✅ 기간 검색 + 좌측 리스트용
    // (동의 로그(1100) 집계 포함)
    $sql = "
      SELECT
        i.cashhome_1000_id,
        i.cashhome_1000_created_at,
        i.cashhome_1000_updated_at,
        i.cashhome_1000_customer_name,
        i.cashhome_1000_customer_phone,
        i.cashhome_1000_loan_amount,
        i.cashhome_1000_loan_purpose,
        i.cashhome_1000_request_memo,
        i.cashhome_1000_user_ip,
        i.cashhome_1000_user_agent,
        i.cashhome_1000_status,
        i.cashhome_1000_admin_note,

        MAX(CASE WHEN c.cashhome_1100_consent_type='privacy' THEN c.cashhome_1100_consented_at END)   AS privacy_at,
        MAX(CASE WHEN c.cashhome_1100_consent_type='privacy' THEN c.cashhome_1100_consent_version END) AS privacy_ver,
        MAX(CASE WHEN c.cashhome_1100_consent_type='marketing' THEN c.cashhome_1100_consented_at END) AS marketing_at

      FROM cashhome_1000_inquiries i
      LEFT JOIN cashhome_1100_consent_logs c
        ON c.cashhome_1100_inquiry_id = i.cashhome_1000_id

      WHERE i.cashhome_1000_created_at BETWEEN :startDT AND :endDT

      GROUP BY
        i.cashhome_1000_id,
        i.cashhome_1000_created_at,
        i.cashhome_1000_updated_at,
        i.cashhome_1000_customer_name,
        i.cashhome_1000_customer_phone,
        i.cashhome_1000_loan_amount,
        i.cashhome_1000_loan_purpose,
        i.cashhome_1000_request_memo,
        i.cashhome_1000_user_ip,
        i.cashhome_1000_user_agent,
        i.cashhome_1000_status,
        i.cashhome_1000_admin_note

      ORDER BY i.cashhome_1000_id DESC
      LIMIT 2000
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([':startDT' => $startDT, ':endDT' => $endDT]);
    $rows = $stmt->fetchAll();

    if ($selectedId > 0) {
        foreach ($rows as $r) {
            if ((int)$r['cashhome_1000_id'] === $selectedId) {
                $selected = $r;
                break;
            }
        }
    }
    // 선택이 없으면 첫 번째 항목 자동 선택
    if (!$selected && !empty($rows)) {
        $selected = $rows[0];
        $selectedId = (int)$selected['cashhome_1000_id'];
    }

} catch (Throwable $e) {
    error_log('[ADMIN LIST ERROR] ' . $e->getMessage());
    $error = '데이터를 불러오지 못했습니다. (서버 로그 확인)';
}

// 상태 라벨(보기용)
function status_label(string $s): string {
    return match ($s) {
        'new' => '신규',
        'contacted' => '연락완료',
        'closed' => '종결',
        default => $s,
    };
}
?>
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow" />
  <title>접수이력</title>
  <style>
    :root{
      --bg:#0B1220;
      --card:rgba(16,26,51,.78);
      --line:rgba(234,240,255,.12);
      --line2:rgba(234,240,255,.08);
      --text:#EAF0FF;
      --muted:#9DB0D0;
      --ok:#6EE7FF;
      --warn:#FBBF24;
      --shadow:0 10px 30px rgba(0,0,0,.35);
      --r1:18px;
      --r2:22px;
    }
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,"Noto Sans KR";background:var(--bg);color:var(--text)}
    a{color:inherit}
    .wrap{max-width:1400px;margin:0 auto;padding:18px 16px 22px}
    .topbar{
      display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
      padding:14px 14px;border:1px solid var(--line);border-radius:var(--r2);
      background:linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02));
      box-shadow:var(--shadow);
    }
    .title h2{margin:0 0 4px;font-size:18px;letter-spacing:-.2px}
    .title .muted{color:var(--muted);font-size:12px}

    .actions{display:flex;gap:8px;flex-wrap:wrap}
    .btn{
      padding:10px 12px;border-radius:999px;border:1px solid var(--line);
      background:rgba(16,26,51,.55);color:var(--text);text-decoration:none;
      font-size:12px;font-weight:800;cursor:pointer;
    }
    .btn:hover{background:rgba(255,255,255,.05)}
    .btn.primary{
      border:0;background:linear-gradient(135deg, rgba(110,231,255,.9), rgba(167,139,250,.9));
      color:#061025;
    }

    .notice{
      margin-top:10px;padding:10px 12px;border-radius:14px;border:1px solid rgba(110,231,255,.25);
      background:rgba(255,255,255,.03);font-size:12px;color:var(--text)
    }
    .err{
      margin-top:10px;padding:10px 12px;border-radius:14px;border:1px solid rgba(255,120,120,.35);
      background:rgba(255,255,255,.03);font-size:12px
    }

    /* ✅ 검색 영역(겹침 해결) */
    .filters{
      margin-top:12px;
      padding:14px;
      border:1px solid var(--line);
      border-radius:var(--r2);
      background:var(--card);
      box-shadow:var(--shadow);
      display:grid;
      grid-template-columns: 1fr 1fr auto auto;
      gap:10px;
      align-items:end;
    }
    .field{display:grid;gap:6px}
    .field label{font-size:12px;color:var(--muted)}
    input[type="date"]{
      width:100%;
      padding:12px 12px;border-radius:14px;border:1px solid var(--line);
      background:rgba(8,12,24,.55);color:var(--text);outline:none;
    }
    input[type="date"]:focus{border-color:rgba(110,231,255,.55);box-shadow:0 0 0 3px rgba(110,231,255,.12)}
    .meta{grid-column:1 / -1;color:var(--muted);font-size:12px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
    @media (max-width: 900px){
      .filters{grid-template-columns:1fr 1fr; }
      .meta{grid-column:1 / -1;}
    }

    /* ✅ 본문 2열 레이아웃(안정감) */
    .layout{
      margin-top:12px;
      display:grid;
      grid-template-columns: 420px 1fr;
      gap:12px;
      min-height: calc(100vh - 240px);
    }
    @media (max-width: 1100px){
      .layout{grid-template-columns:1fr; }
    }

    .panel{
      border:1px solid var(--line);
      border-radius:var(--r2);
      background:var(--card);
      box-shadow:var(--shadow);
      overflow:hidden;
      display:flex;flex-direction:column;
      min-height: 420px;
    }
    .panelHead{
      padding:12px 14px;border-bottom:1px solid var(--line2);
      display:flex;align-items:center;justify-content:space-between;gap:10px;
      background:rgba(11,18,32,.35);
    }
    .panelHead b{font-size:13px}
    .count{color:var(--muted);font-size:12px}

    /* 좌측 리스트 */
    .list{overflow:auto;max-height: calc(100vh - 330px);}
    .item{
      padding:12px 14px;border-bottom:1px solid var(--line2);
      text-decoration:none;display:block;
      transition: background .15s ease;
    }
    .item:hover{background:rgba(255,255,255,.04)}
    .item.on{background:rgba(255,255,255,.06)}
    .row1{display:flex;align-items:center;justify-content:space-between;gap:10px}
    .name{font-weight:900}
    .idchip{color:var(--muted);font-size:12px}
    .row2{margin-top:6px;color:var(--muted);font-size:12px;display:flex;gap:10px;flex-wrap:wrap}
    .chips{margin-top:8px;display:flex;gap:8px;flex-wrap:wrap}
    .chip{
      display:inline-flex;align-items:center;gap:6px;
      padding:4px 8px;border-radius:999px;
      border:1px solid var(--line);
      background:rgba(255,255,255,.03);
      font-size:12px;color:var(--text)
    }
    .chip.warn{color:var(--warn)}
    .chip.ok{color:var(--ok)}

    /* 우측 상세 */
    .detailBody{padding:14px;overflow:auto;max-height: calc(100vh - 330px);}
    .detailTitle{font-size:18px;margin:0 0 10px;letter-spacing:-.2px}
    .kv{display:grid;grid-template-columns:140px 1fr;gap:8px 12px;font-size:13px}
    .k{color:var(--muted)}
    .v{color:var(--text)}
    .memoBox{
      margin-top:12px;padding:12px;border-radius:16px;border:1px solid var(--line);
      background:rgba(8,12,24,.45);white-space:pre-wrap;color:var(--text);font-size:13px;
      min-height:84px;
    }
    .subhr{margin:14px 0;height:1px;background:var(--line2)}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="title">
        <h2>접수이력</h2>
        <div class="muted">기간 검색 + 좌측 리스트 선택 → 우측 상세 확인</div>
      </div>
      <div class="actions">
        <a class="btn" href="./">홈</a>
        <a class="btn" href="admin_inquiries.php?logout=1">로그아웃</a>
      </div>
    </div>

    <?php if ($notice): ?>
      <div class="notice"><?=h($notice)?></div>
    <?php endif; ?>
    <?php if ($error): ?>
      <div class="err"><?=h($error)?></div>
    <?php endif; ?>

    <form class="filters" method="get" action="admin_inquiries.php">
      <div class="field">
        <label for="start">시작일</label>
        <input id="start" name="start" type="date" value="<?=h($start)?>">
      </div>
      <div class="field">
        <label for="end">종료일</label>
        <input id="end" name="end" type="date" value="<?=h($end)?>">
      </div>

      <button class="btn primary" type="submit">검색</button>
      <a class="btn" href="admin_inquiries.php?start=<?=h($defaultStart)?>&end=<?=h($today)?>">초기화</a>

      <div class="meta">
        <span>표시 건수: <b><?=h((string)count($rows))?></b> (최대 2000)</span>
        <?php if ($selectedId > 0): ?>
          <span>선택: #<?=h((string)$selectedId)?></span>
        <?php endif; ?>
      </div>
    </form>

    <div class="layout">
      <!-- 좌측 리스트 -->
      <div class="panel">
        <div class="panelHead">
          <b>리스트</b>
          <span class="count">최신순</span>
        </div>
        <div class="list">
          <?php if (!$rows): ?>
            <div style="padding:14px;color:var(--muted);font-size:12px;">해당 기간에 접수 내역이 없습니다.</div>
          <?php endif; ?>

          <?php foreach ($rows as $r): ?>
            <?php
              $id = (int)$r['cashhome_1000_id'];
              $on = ($id === $selectedId);
              $pOk = !empty($r['privacy_at']);
              $mOk = !empty($r['marketing_at']);
              $st = (string)$r['cashhome_1000_status'];
              $qs = http_build_query([
                  'start' => $start,
                  'end' => $end,
                  'id' => $id,
              ]);
            ?>
            <a class="item <?= $on ? 'on' : '' ?>" href="admin_inquiries.php?<?=h($qs)?>">
              <div class="row1">
                <div class="name"><?=h((string)$r['cashhome_1000_customer_name'])?></div>
                <div class="idchip">#<?=h((string)$id)?></div>
              </div>
              <div class="row2">
                <span><?=h((string)$r['cashhome_1000_created_at'])?></span>
                <span>·</span>
                <span><?=h((string)$r['cashhome_1000_customer_phone'])?></span>
              </div>
              <div class="chips">
                <span class="chip <?= $st==='new' ? 'warn' : '' ?>">상태: <?=h(status_label($st))?></span>
                <span class="chip <?= $pOk ? 'ok' : '' ?>">개인정보: <?=h(consent_text($pOk))?></span>
                <span class="chip <?= $mOk ? 'ok' : '' ?>">마케팅: <?=h(consent_text($mOk))?></span>
              </div>
            </a>
          <?php endforeach; ?>
        </div>
      </div>

      <!-- 우측 상세 -->
      <div class="panel">
        <div class="panelHead">
          <b>상세 처리 · #<?=h((string)$selectedId)?></b>
          <span class="count"><?= $selected ? '선택된 항목' : '' ?></span>
        </div>

        <div class="detailBody">
          <?php if (!$selected): ?>
            <div style="color:var(--muted);font-size:12px;">선택된 항목이 없습니다.</div>
          <?php else: ?>
            <?php
              $pOk = !empty($selected['privacy_at']);
              $mOk = !empty($selected['marketing_at']);
            ?>
            <h3 class="detailTitle">접수 정보</h3>
            <div class="kv">
              <div class="k">접수일시</div><div class="v"><?=h((string)$selected['cashhome_1000_created_at'])?></div>
              <div class="k">이름</div><div class="v"><?=h((string)$selected['cashhome_1000_customer_name'])?></div>
              <div class="k">연락처</div><div class="v"><?=h((string)$selected['cashhome_1000_customer_phone'])?></div>
              <div class="k">희망금액</div><div class="v"><?=h((string)($selected['cashhome_1000_loan_amount'] ?? ''))?></div>
              <div class="k">자금용도</div><div class="v"><?=h((string)($selected['cashhome_1000_loan_purpose'] ?? ''))?></div>

              <div class="k">IP</div><div class="v"><?=h((string)($selected['cashhome_1000_user_ip'] ?? ''))?></div>
              <div class="k">User-Agent</div><div class="v" style="word-break:break-word;"><?=h((string)($selected['cashhome_1000_user_agent'] ?? ''))?></div>

              <div class="k">동의(개인)</div>
              <div class="v">
                <?=h(consent_text($pOk))?>
                <?php if ($pOk): ?>
                  <span style="color:var(--muted)"> (<?=h((string)($selected['privacy_ver'] ?? ''))?>)</span>
                <?php endif; ?>
              </div>

              <div class="k">동의(마케팅)</div>
              <div class="v"><?=h(consent_text($mOk))?></div>

              <div class="k">수정일시</div><div class="v"><?=h((string)($selected['cashhome_1000_updated_at'] ?? ''))?></div>
              <div class="k">처리상태</div><div class="v"><?=h(status_label((string)$selected['cashhome_1000_status']))?></div>
            </div>

            <div class="subhr"></div>

            <h3 class="detailTitle" style="font-size:15px;margin:0 0 8px;">요청사항</h3>
            <div class="memoBox"><?=h((string)($selected['cashhome_1000_request_memo'] ?? ''))?></div>

            <div class="subhr"></div>

            <h3 class="detailTitle" style="font-size:15px;margin:0 0 8px;">관리자 메모</h3>
            <div class="memoBox"><?=h((string)($selected['cashhome_1000_admin_note'] ?? ''))?></div>

            <div style="margin-top:10px;color:var(--muted);font-size:12px;">
              ※ 상태 변경/메모 저장 기능은 이어서 붙이면 됩니다. (현재 화면은 UI 안정화/표시 개선만 반영)
            </div>
          <?php endif; ?>
        </div>
      </div>
    </div>
  </div>
</body>
</html>