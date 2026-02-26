<?php

declare(strict_types=1);

session_start();
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self' 'unsafe-inline' https: data:;");

function h(string $s): string
{
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// index.php와 동일하게 맞추세요
const PRIVACY_POLICY_VERSION = 'v1';
const MARKETING_POLICY_VERSION = 'v1'; // (표시용. 실제 저장은 index.php 구조에 맞춰 version 하나로 통일)

// ✅ index.php에서 입력 검증 통과하면 세션에 draft 저장됨
$draft = $_SESSION['cashhome_inquiry_draft'] ?? null;
$hasDraft = is_array($draft) && trim((string)($draft['name'] ?? '')) !== '' && trim((string)($draft['phone'] ?? '')) !== '';

// ✅ return 파라미터 지원 (index.php에서 넘어올 때 사용)
$return = rawurldecode((string)($_GET['return'] ?? 'index.php#apply'));
if ($return === '') $return = 'index.php#apply';

// 탭(privacy|marketing)
$tab = (string)($_GET['tab'] ?? 'privacy');
if (!in_array($tab, ['privacy', 'marketing'], true)) $tab = 'privacy';

if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ✅ index.php가 기대하는 동의 세션 구조로 통일
// index.php 기대:
// $_SESSION['cashhome_consent'] = [
//   'privacy'=>1, 'marketing'=>1, 'version'=>'v1', 'consented_at'=>'YYYY-mm-dd HH:ii:ss'
// ];
if (empty($_SESSION['cashhome_consent']) || !is_array($_SESSION['cashhome_consent'])) {
  $_SESSION['cashhome_consent'] = [
    'privacy' => 0,
    'marketing' => 0,
    'version' => PRIVACY_POLICY_VERSION,
    'consented_at' => null,
    // 아래 4개는 표시/상세 증적용(있어도 되고 없어도 됨)
    'privacy_at' => null,
    'marketing_at' => null,
    'privacy_ver' => PRIVACY_POLICY_VERSION,
    'marketing_ver' => MARKETING_POLICY_VERSION,
  ];
} else {
  // 누락 키 보정
  $_SESSION['cashhome_consent']['privacy'] = !empty($_SESSION['cashhome_consent']['privacy']) ? 1 : 0;
  $_SESSION['cashhome_consent']['marketing'] = !empty($_SESSION['cashhome_consent']['marketing']) ? 1 : 0;
  $_SESSION['cashhome_consent']['version'] = (string)($_SESSION['cashhome_consent']['version'] ?? PRIVACY_POLICY_VERSION);
  $_SESSION['cashhome_consent']['consented_at'] = $_SESSION['cashhome_consent']['consented_at'] ?? null;

  $_SESSION['cashhome_consent']['privacy_at'] = $_SESSION['cashhome_consent']['privacy_at'] ?? null;
  $_SESSION['cashhome_consent']['marketing_at'] = $_SESSION['cashhome_consent']['marketing_at'] ?? null;
  $_SESSION['cashhome_consent']['privacy_ver'] = (string)($_SESSION['cashhome_consent']['privacy_ver'] ?? PRIVACY_POLICY_VERSION);
  $_SESSION['cashhome_consent']['marketing_ver'] = (string)($_SESSION['cashhome_consent']['marketing_ver'] ?? MARKETING_POLICY_VERSION);
}

$error = '';
$success = '';

// ✅ draft 없으면 동의 페이지 접근 자체를 막음(증적 목적)
if (!$hasDraft) {
  $error = "상담신청 입력(성함/연락처/희망금액/자금용도)을 먼저 완료한 후 동의할 수 있습니다.\n상담신청 화면으로 이동해 입력을 완료해주세요.";
}

// POST 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // draft 없으면 동의 처리 차단
  if (!$hasDraft) {
    $error = "상담신청 입력을 먼저 완료한 후 동의할 수 있습니다.\n상담신청 화면으로 이동해 입력을 완료해주세요.";
  } else {
    $token = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
      $error = '요청이 만료되었거나 올바르지 않습니다. 새로고침 후 다시 시도해주세요.';
    } else {
      $action = (string)($_POST['action'] ?? '');
      $now = date('Y-m-d H:i:s');

      if ($action === 'agree_privacy') {
        $_SESSION['cashhome_consent']['privacy'] = 1;
        $_SESSION['cashhome_consent']['privacy_at'] = $now;
        $_SESSION['cashhome_consent']['privacy_ver'] = PRIVACY_POLICY_VERSION;

        // ✅ index.php가 쓰는 공통 증적(버전/시각)
        $_SESSION['cashhome_consent']['version'] = PRIVACY_POLICY_VERSION;
        $_SESSION['cashhome_consent']['consented_at'] = $now;

        $success = '개인정보 처리방침에 동의했습니다.';
        $tab = 'marketing'; // 다음 탭 유도
      } elseif ($action === 'agree_marketing') {

        $_SESSION['cashhome_consent']['marketing'] = 1;
        $_SESSION['cashhome_consent']['marketing_at'] = $now;
        $_SESSION['cashhome_consent']['marketing_ver'] = MARKETING_POLICY_VERSION;

        $_SESSION['cashhome_consent']['version'] = PRIVACY_POLICY_VERSION;
        $_SESSION['cashhome_consent']['consented_at'] = $now;

        // 🔥 개인정보 + 마케팅 둘 다 완료 시 자동 복귀
        if (!empty($_SESSION['cashhome_consent']['privacy'])) {

          $redirectUrl = 'index.php#apply2';

          if (strpos($redirectUrl, '#') !== false) {
            list($base, $hash) = explode('#', $redirectUrl, 2);
            $redirectUrl = $base . '?consent=done#' . $hash;
          } else {
            $redirectUrl .= '?consent=done';
          }

          header("Location: " . $redirectUrl);
          exit;
        }

        $success = '마케팅 수신에 동의했습니다.';
        $tab = 'marketing';
      } elseif ($action === 'reset') {
        $_SESSION['cashhome_consent'] = [
          'privacy' => 0,
          'marketing' => 0,
          'version' => PRIVACY_POLICY_VERSION,
          'consented_at' => null,
          'privacy_at' => null,
          'marketing_at' => null,
          'privacy_ver' => PRIVACY_POLICY_VERSION,
          'marketing_ver' => MARKETING_POLICY_VERSION,
        ];
        $success = '동의 상태를 초기화했습니다.';
        $tab = 'privacy';
      } else {
        $error = '잘못된 요청입니다.';
      }

      // CSRF rotate
      $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
  }
}

$consent = $_SESSION['cashhome_consent'];
$privacyDone = !empty($consent['privacy']);
$marketingDone = !empty($consent['marketing']);
$allDone = $privacyDone && $marketingDone;

// 회사 정보(표시용)
$brandKr = '이케쉬대부';
$brandEn = 'ECASH';
$companyNameLine = $brandKr . ' (' . $brandEn . ')';
$companyAddr = '충남 천안시 동남구 봉명동 9번지';
$companyTel  = '010-5651-0030';
$companyOwner = '이주진';

/**
 * ===== 개인정보 처리방침 전문 =====
 */
$privacyText = <<<TXT
[개인정보 처리방침 전문] (버전: {PRIVACY_POLICY_VERSION})

{$companyNameLine}(이하 “회사”)는 「개인정보 보호법」 등 관련 법령을 준수하며, 이용자의 개인정보를 보호하고 권익을 보호하기 위하여 다음과 같이 개인정보 처리방침을 수립·공개합니다. 본 처리방침은 회사가 제공하는 상담신청(문의) 서비스에 적용됩니다.

1. 개인정보의 처리 목적
회사는 다음의 목적을 위하여 개인정보를 처리합니다. 처리한 개인정보는 다음 목적 이외의 용도로는 이용되지 않으며, 이용 목적이 변경되는 경우에는 관련 법령에 따라 별도의 동의를 받는 등 필요한 조치를 이행합니다.
(1) 상담 신청 접수 및 상담 진행: 상담 신청 접수 확인, 연락, 상담 내용 확인 및 응대, 민원 처리, 분쟁 대응
(2) 서비스 운영 및 보안: 비정상 이용 탐지, 부정 이용 방지, 서비스 안정성 확보, 접속기록 등 보안 로그 관리

2. 처리하는 개인정보의 항목
회사는 최소한의 개인정보만을 수집합니다.
(1) 상담 신청 시
- 필수: 성함, 연락처(전화번호), 개인정보 동의 여부 및 동의 일시/버전
- 선택: 희망금액, 자금용도, 요청사항(상담내용)
(2) 자동 수집 항목
- 접속 IP, 접속 일시, User-Agent(브라우저 정보), 서비스 이용기록(접속기록/로그)

3. 개인정보의 처리 및 보유 기간
회사는 원칙적으로 개인정보 처리 목적이 달성되면 지체 없이 파기합니다.
(1) 상담 신청(문의) 관련 정보: 목적 달성 후 지체 없이 파기
다만, 분쟁/민원 처리 또는 재확인이 필요한 경우 최대 3년 범위에서 보관할 수 있습니다(내부 방침).
(2) 접속기록(로그): 최대 1년 (보안 목적/부정 이용 방지)
(3) 법령에 따른 보관: 관계 법령에서 정한 보관 의무가 있는 경우 해당 기간 동안 보관

4. 개인정보의 제3자 제공
회사는 원칙적으로 이용자의 개인정보를 제3자에게 제공하지 않습니다.
다만, 이용자가 사전에 동의한 경우, 법령에 특별한 규정이 있거나 관계 기관의 적법한 절차에 따른 요청이 있는 경우에는 예외로 합니다.
※ 현재 회사는 상담신청 서비스와 관련하여 이용자 개인정보를 제3자에게 제공하지 않습니다(제공 시 항목/받는 자/목적/보유기간을 고지).

5. 개인정보 처리의 위탁
회사는 원활한 서비스 제공을 위하여 개인정보 처리업무를 외부에 위탁할 수 있으며, 위탁 시 관련 법령에 따라 위탁계약 및 수탁자 관리·감독을 실시합니다.
※ 현재 회사는 상담신청 서비스와 관련하여 개인정보 처리업무를 외부에 위탁하지 않습니다(향후 위탁 발생 시 공개).

6. 이용자의 권리·의무 및 행사 방법
이용자는 회사에 대해 개인정보 열람, 정정·삭제, 처리정지, 동의 철회 등을 요청할 수 있습니다.
권리 행사는 아래 “개인정보 보호 책임자”에게 서면 또는 전화 등으로 요청 가능하며 회사는 지체 없이 조치합니다.
다만, 관련 법령에 따라 제한될 수 있습니다.

7. 개인정보의 파기 절차 및 방법
보유기간 경과 또는 목적 달성 시 지체 없이 파기합니다.
- 전자적 파일: 복구 불가능한 방법으로 영구 삭제
- 출력물: 분쇄 또는 소각

8. 개인정보의 안전성 확보 조치
취급자 최소화 및 교육, 접근권한 관리, 접속기록 보관 및 위·변조 방지, 보안조치 등을 시행합니다.

9. 개인정보 보호 책임자 및 문의처
- 개인정보 보호 책임자: {$companyOwner}
- 상호: {$companyNameLine}
- 주소: {$companyAddr}
- 문의(대표전화): {$companyTel}

10. 처리방침 변경
본 방침은 {PRIVACY_POLICY_VERSION} 버전으로 적용됩니다. 변경 시 웹사이트를 통해 공지합니다.
- 공고일자: 2026-02-21
- 시행일자: 2026-02-21
TXT;

$privacyText = str_replace('{PRIVACY_POLICY_VERSION}', PRIVACY_POLICY_VERSION, $privacyText);

/**
 * ===== 마케팅 정보 수신 동의 전문 =====
 */
$marketingText = <<<TXT
[마케팅 정보 수신 동의 전문] (버전: {MARKETING_POLICY_VERSION})

1. 동의 목적
회사는 이용자에게 이벤트/프로모션/상품 안내, 신규 서비스 안내 등 광고성 정보를 제공하기 위하여 마케팅 정보 수신 동의를 받습니다.

2. 수집·이용 항목
- 연락처(전화번호)
- 마케팅 수신 동의 여부 및 동의 일시/버전
- (보안 목적) 접속 IP, User-Agent 등 접속기록 일부

3. 이용 방법
- 전화, 문자(SMS/MMS) 등으로 안내할 수 있습니다.
- 실제 발송 채널/내용은 회사 운영 정책에 따라 달라질 수 있습니다.

4. 보유 및 이용 기간
- 동의일로부터 “동의 철회 시”까지 보유·이용합니다.
- 단, 관계 법령 또는 분쟁 처리 등 필요한 경우에는 해당 목적 달성 시까지 최소 범위에서 보관할 수 있습니다.

5. 동의 거부 권리 및 불이익
- 이용자는 동의를 거부할 권리가 있습니다.
- 다만, 본 사이트는 “상담 접수 진행을 위해 마케팅 동의를 필수로 요구”하도록 설정되어 있어 동의하지 않으면 상담 접수 진행이 제한됩니다.

6. 동의 철회
- 동의 철회는 “개인정보 보호 책임자”에게 요청하여 언제든지 가능합니다.
- 문의(대표전화): {$companyTel}

- 상호: {$companyNameLine}
- 주소: {$companyAddr}
TXT;

$marketingText = str_replace('{MARKETING_POLICY_VERSION}', MARKETING_POLICY_VERSION, $marketingText);
?>
<!doctype html>
<html lang="ko">

<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow" />
  <title>동의 페이지</title>
  <style>
    :root {
      --bg: #0B1220;
      --card: rgba(16, 26, 51, .85);
      --line: rgba(234, 240, 255, .12);
      --text: #EAF0FF;
      --muted: #9DB0D0;
      --ok: #6EE7FF;
      --btn: linear-gradient(135deg, rgba(110, 231, 255, .9), rgba(167, 139, 250, .9));
    }

    body {
      margin: 0;
      font-family: system-ui, "Noto Sans KR";
      background: var(--bg);
      color: var(--text)
    }

    .wrap {
      max-width: 920px;
      margin: 0 auto;
      padding: 22px 16px 60px
    }

    .top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap
    }

    .pill {
      display: inline-flex;
      gap: 8px;
      align-items: center;
      padding: 6px 10px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255, 255, 255, .03);
      color: var(--muted);
      font-size: 12px
    }

    .card {
      margin-top: 12px;
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 16px
    }

    .tabs {
      display: flex;
      gap: 8px;
      flex-wrap: wrap
    }

    .tab {
      padding: 10px 12px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, .03);
      color: var(--muted);
      text-decoration: none;
      font-weight: 800;
      font-size: 13px
    }

    .tab.on {
      background: rgba(255, 255, 255, .08);
      color: var(--text)
    }

    .doc {
      margin-top: 12px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(8, 12, 24, .55);
      padding: 12px;
      height: 360px;
      overflow: auto;
      white-space: pre-wrap;
      font-size: 12px;
      line-height: 1.55
    }

    .btnRow {
      margin-top: 12px;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center
    }

    button,
    .btn {
      padding: 12px 14px;
      border-radius: 999px;
      border: 0;
      cursor: pointer;
      font-weight: 900;
      background: var(--btn);
      color: #061025;
      text-decoration: none
    }

    button[disabled] {
      opacity: .45;
      cursor: not-allowed
    }

    .ghost {
      background: transparent;
      border: 1px solid var(--line);
      color: var(--text)
    }

    .err,
    .okmsg {
      margin-top: 12px;
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid rgba(255, 120, 120, .35);
      background: rgba(255, 255, 255, .03);
      white-space: pre-wrap
    }

    .okmsg {
      border-color: rgba(110, 231, 255, .35)
    }

    .muted {
      color: var(--muted);
      font-size: 12px
    }

    .status {
      display: grid;
      gap: 6px;
      margin-top: 10px
    }

    .sline {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center
    }

    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, .03);
      font-size: 12px
    }

    .badge.ok {
      color: var(--ok)
    }
  </style>
</head>

<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h2 style="margin:0 0 6px;">동의 페이지</h2>
        <div class="muted">상담 접수를 진행하려면 <b>개인정보 처리방침</b>과 <b>마케팅 수신</b>에 모두 동의해야 합니다.</div>
      </div>
      <div class="pill">버전: 개인정보 <?= h(PRIVACY_POLICY_VERSION) ?> · 마케팅 <?= h(MARKETING_POLICY_VERSION) ?></div>
    </div>

    <div class="card">
      <div class="tabs">
        <a class="tab <?= $tab === 'privacy' ? 'on' : '' ?>" href="consent.php?tab=privacy&return=<?= h(urlencode($return)) ?>">개인정보 처리방침</a>
        <a class="tab <?= $tab === 'marketing' ? 'on' : '' ?>" href="consent.php?tab=marketing&return=<?= h(urlencode($return)) ?>">마케팅 수신 동의</a>
        <a class="tab" href="<?= h($return) ?>">상담신청으로 돌아가기</a>
      </div>

      <div class="status">
        <div class="sline">
          <span class="badge <?= $privacyDone ? 'ok' : '' ?>">개인정보: <?= $privacyDone ? '동의완료' : '미동의' ?></span>
          <?php if ($privacyDone): ?>
            <span class="muted">동의일시: <?= h((string)($consent['privacy_at'] ?? $consent['consented_at'] ?? '')) ?></span>
          <?php endif; ?>
        </div>
        <div class="sline">
          <span class="badge <?= $marketingDone ? 'ok' : '' ?>">마케팅: <?= $marketingDone ? '동의완료' : '미동의' ?></span>
          <?php if ($marketingDone): ?>
            <span class="muted">동의일시: <?= h((string)($consent['marketing_at'] ?? $consent['consented_at'] ?? '')) ?></span>
          <?php endif; ?>
        </div>
      </div>

      <?php if ($error): ?><div class="err" role="alert"><?= h($error) ?></div><?php endif; ?>
      <?php if ($success): ?><div class="okmsg" role="status" aria-live="polite"><?= h($success) ?></div><?php endif; ?>

      <div class="doc" id="doc">
        <?php if ($tab === 'privacy'): ?>
          <?= h($privacyText) ?>
        <?php else: ?>
          <?= h($marketingText) ?>
        <?php endif; ?>
      </div>

      <div class="btnRow">
        <form method="post" action="consent.php?tab=<?= h($tab) ?>&return=<?= h(urlencode($return)) ?>" style="margin:0;">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <?php if ($tab === 'privacy'): ?>
            <input type="hidden" name="action" value="agree_privacy">
            <button id="agreeBtn" type="submit" <?= $hasDraft ? 'disabled' : 'disabled' ?>>끝까지 읽고 개인정보 동의하기</button>
          <?php else: ?>
            <input type="hidden" name="action" value="agree_marketing">
            <button id="agreeBtn" type="submit" <?= $hasDraft ? 'disabled' : 'disabled' ?>>끝까지 읽고 마케팅 동의하기</button>
          <?php endif; ?>
        </form>

        <a class="btn ghost" href="<?= h($return) ?>">상담신청으로</a>

        <form method="post" action="consent.php?tab=<?= h($tab) ?>&return=<?= h(urlencode($return)) ?>" style="margin:0;">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="reset">
          <button class="ghost" type="submit">동의 초기화</button>
        </form>

        <?php if ($allDone): ?>
          <span class="muted">✅ 모든 동의 완료! 이제 상담신청 화면으로 돌아가 접수 버튼을 눌러주세요.</span>
        <?php endif; ?>
      </div>

      <div class="muted" style="margin-top:10px;">
        ※ 스크롤을 문서 끝까지 내려야 “동의하기” 버튼이 활성화됩니다.
      </div>

      <?php if (!$hasDraft): ?>
        <div class="err" style="margin-top:12px;">
          입력값이 확인되지 않아 동의 진행이 제한됩니다.<br>
          <a class="btn ghost" href="<?= h($return) ?>" style="display:inline-block;margin-top:10px;">상담신청으로 돌아가 입력하기</a>
        </div>
      <?php endif; ?>

    </div>
  </div>

  <script>
    (function() {
      // ✅ 에러/성공은 팝업으로도 알려주기
      const err = <?= json_encode($error, JSON_UNESCAPED_UNICODE) ?>;
      const ok = <?= json_encode($success, JSON_UNESCAPED_UNICODE) ?>;
      if (err) alert(err);
      if (ok) alert(ok);

      const doc = document.getElementById('doc');
      const btn = document.getElementById('agreeBtn');
      if (!doc || !btn) return;

      const hasDraft = <?= $hasDraft ? 'true' : 'false' ?>;
      if (!hasDraft) {
        // draft 없으면 버튼은 계속 비활성
        btn.disabled = true;
        return;
      }

      const check = () => {
        const nearBottom = (doc.scrollTop + doc.clientHeight) >= (doc.scrollHeight - 2);
        if (nearBottom) btn.disabled = false;
      };

      doc.addEventListener('scroll', check, {
        passive: true
      });
      setTimeout(check, 60);
    })();
  </script>
</body>

</html>