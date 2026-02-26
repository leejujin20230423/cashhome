<?php

/**
 * ===========================
 * 파일명: document_upload.php
 * 역할: 카메라 촬영 + upload_document.php 업로드 + 토큰 사용완료(mark_used) + (추가) 업로드완료 메일 트리거(index.php upload_notice)
 * ✅ 무한 리다이렉트 방지: 세션 없으면 안내만 하고 document_token.php로 강제 리다이렉트 금지
 * ===========================
 */

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

function cashhome_boot_session(): void
{
    $isHttps = (
        (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
        || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
    );

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
}
cashhome_boot_session();

header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https: blob:; connect-src 'self' https:; media-src 'self' blob:;");
header('Permissions-Policy: camera=(self)');

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ✅ index.php upload_notice에서 쓰는 csrf_token을 이 페이지에서도 항상 보장
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ===== DB 설정 =====
const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

function cashhome_pdo(): PDO
{
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

/** 토큰 사용완료 처리 (신/구 컬럼 둘 다 지원) */
function mark_token_used(PDO $pdo, int $inquiryId, string $token): bool
{
    if ($inquiryId <= 0 || !preg_match('/^\d{6}$/', $token)) return false;

    $now = date('Y-m-d H:i:s');

    $st = $pdo->prepare("
        UPDATE cashhome_1000_inquiries
        SET
          cashhome_1000_doc_token_status = CASE WHEN cashhome_1000_doc_token = :tkA THEN 2 ELSE cashhome_1000_doc_token_status END,
          cashhome_1000_doc_token_used_at = CASE WHEN cashhome_1000_doc_token = :tkB THEN :nowA ELSE cashhome_1000_doc_token_used_at END,

          doc_token_status = CASE WHEN doc_token = :tkC THEN 2 ELSE doc_token_status END,
          doc_token_used_at = CASE WHEN doc_token = :tkD THEN :nowB ELSE doc_token_used_at END
        WHERE cashhome_1000_id = :id
          AND (cashhome_1000_doc_token = :tkE OR doc_token = :tkF)
          AND (
            (cashhome_1000_doc_token = :tkG AND cashhome_1000_doc_token_status = 1)
            OR
            (doc_token = :tkH AND doc_token_status = 1)
          )
        LIMIT 1
    ");

    $st->execute([
        ':nowA' => $now,
        ':nowB' => $now,
        ':id'   => $inquiryId,

        ':tkA'  => $token,
        ':tkB'  => $token,
        ':tkC'  => $token,
        ':tkD'  => $token,
        ':tkE'  => $token,
        ':tkF'  => $token,
        ':tkG'  => $token,
        ':tkH'  => $token,
    ]);

    return $st->rowCount() > 0;
}

// CSRF (mark_used)
if (empty($_SESSION['csrf_token_doc_upload'])) {
    $_SESSION['csrf_token_doc_upload'] = bin2hex(random_bytes(32));
}

// mark_used AJAX
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'mark_used') {
    header('Content-Type: application/json; charset=utf-8');

    $csrf = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token_doc_upload'], $csrf)) {
        echo json_encode(['ok' => false, 'message' => '요청이 만료되었습니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $iid = (int)($_SESSION['cashhome_doc_upload_inquiry_id'] ?? 0);
    $tk  = (string)($_SESSION['cashhome_doc_upload_token'] ?? '');
    if ($iid <= 0 || !preg_match('/^\d{6}$/', $tk)) {
        echo json_encode(['ok' => false, 'message' => '세션이 만료되었습니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    try {
        $pdo = cashhome_pdo();
        $ok = mark_token_used($pdo, $iid, $tk);
        if (!$ok) {
            echo json_encode(['ok' => false, 'message' => '토큰 사용완료 처리 실패'], JSON_UNESCAPED_UNICODE);
            exit;
        }
        $_SESSION['csrf_token_doc_upload'] = bin2hex(random_bytes(32));
        echo json_encode(['ok' => true, 'csrf_token' => $_SESSION['csrf_token_doc_upload']], JSON_UNESCAPED_UNICODE);
        exit;
    } catch (Throwable $e) {
        error_log('[MARK_USED ERROR] ' . $e->getMessage());
        echo json_encode(['ok' => false, 'message' => '서버 오류'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

// 페이지 접근
$inquiryId = (int)($_SESSION['cashhome_doc_upload_inquiry_id'] ?? 0);
$showToken = (string)($_SESSION['cashhome_doc_upload_token'] ?? '');

$name = '';
$phone = '';

if ($inquiryId > 0) {
    try {
        $pdo = cashhome_pdo();
        $st = $pdo->prepare("SELECT cashhome_1000_customer_name, cashhome_1000_customer_phone FROM cashhome_1000_inquiries WHERE cashhome_1000_id = :id LIMIT 1");
        $st->execute([':id' => $inquiryId]);
        $row = $st->fetch();
        if ($row) {
            $name = (string)($row['cashhome_1000_customer_name'] ?? '');
            $phone = (string)($row['cashhome_1000_customer_phone'] ?? '');
        }
    } catch (Throwable $e) {
        error_log('[DOC_UPLOAD] fetch inquiry error: ' . $e->getMessage());
    }
}
?>
<!doctype html>
<html lang="ko">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#0B1220" />
    <title>서류 제출</title>
    <style>
        :root {
            --bg: #0B1220;
            --card: rgba(16, 26, 51, .78);
            --line: rgba(234, 240, 255, .12);
            --text: #EAF0FF;
            --muted: #9DB0D0;
            --shadow: 0 10px 30px rgba(0, 0, 0, .35);
            --r2: 24px;
            --accent: #6EE7FF;
            --accent2: #A78BFA;
        }

        * {
            box-sizing: border-box
        }

        body {
            margin: 0;
            font-family: ui-sans-serif, system-ui, "Noto Sans KR";
            background: radial-gradient(1200px 600px at 20% -10%, rgba(110, 231, 255, .18), transparent 60%), radial-gradient(900px 520px at 90% 10%, rgba(167, 139, 250, .16), transparent 55%), var(--bg);
            color: var(--text);
            padding: 18px;
        }

        .wrap {
            max-width: 820px;
            margin: 0 auto;
            display: grid;
            gap: 12px
        }

        .card {
            background: var(--card);
            border: 1px solid var(--line);
            border-radius: var(--r2);
            box-shadow: var(--shadow);
            padding: 16px
        }

        h1 {
            margin: 0 0 8px;
            font-size: 18px
        }

        .muted {
            color: var(--muted);
            font-size: 12px
        }

        .pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 10px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            color: var(--muted);
            font-size: 12px;
            font-weight: 900
        }

        .row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 10px
        }

        @media (max-width:720px) {
            .row {
                grid-template-columns: 1fr
            }
        }

        label {
            font-size: 12px;
            color: var(--muted);
            display: block;
            margin-bottom: 6px
        }

        select {
            width: 100%;
            padding: 12px;
            border-radius: 14px;
            border: 1px solid var(--line);
            background: rgba(8, 12, 24, .55);
            color: var(--text);
            outline: none
        }

        .btns {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 10px
        }

        .btn {
            padding: 10px 14px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .04);
            color: var(--text);
            font-weight: 900;
            font-size: 13px;
            cursor: pointer
        }

        .btn.primary {
            border: 0;
            background: linear-gradient(135deg, rgba(110, 231, 255, .92), rgba(167, 139, 250, .92));
            color: #061025
        }

        .btn[disabled] {
            opacity: .45;
            cursor: not-allowed
        }

        video {
            width: 100%;
            max-height: 420px;
            border-radius: 18px;
            border: 1px solid rgba(234, 240, 255, .12);
            background: rgba(8, 12, 24, .55)
        }

        .mini {
            padding: 14px;
            border-radius: var(--r2);
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03)
        }

        .shot {
            display: grid;
            grid-template-columns: 96px 1fr auto;
            gap: 10px;
            align-items: center
        }

        .shot img {
            width: 96px;
            height: 96px;
            object-fit: cover;
            border-radius: 14px;
            border: 1px solid rgba(234, 240, 255, .12)
        }

        .tiny {
            font-size: 11px;
            color: rgba(157, 176, 208, .92)
        }

        .warn {
            padding: 12px;
            border-radius: 16px;
            border: 1px solid rgba(255, 180, 120, .35);
            background: rgba(255, 255, 255, .03);
            color: #FFE1C7;
            font-size: 12px
        }

        a.link {
            color: var(--accent);
            text-decoration: none;
            font-weight: 900
        }
    </style>
</head>

<body>
    <div class="wrap">
        <div class="card">
            <h1>서류 제출</h1>

            <?php if ($inquiryId <= 0): ?>
                <div class="warn">
                    인증 정보(세션)가 없습니다.<br />
                    아래 링크에서 <b>인증코드(6자리)</b>를 다시 입력해주세요.<br /><br />
                    <a class="link" href="document_token.php">👉 인증코드 입력하러 가기</a>
                </div>
            <?php else: ?>
                <div class="muted">신청자: <b><?= h($name) ?></b> / 연락처: <b><?= h($phone) ?></b></div>
                <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
                    <span class="pill">접수번호 #<?= h((string)$inquiryId) ?></span>
                    <span class="pill">토큰 <?= h($showToken) ?></span>
                </div>
                <div class="muted" style="margin-top:10px;">
                    ※ 카메라 시작 → 촬영(여러 장) → 업로드<br />
                    ※ 업로드 완료 시 토큰이 <b>사용완료</b> 처리됩니다.
                </div>
            <?php endif; ?>
        </div>

        <?php if ($inquiryId > 0): ?>
            <div class="card">
                <div class="row">
                    <div>
                        <label for="docType">서류 유형</label>
                        <select id="docType">
                            <option value="id_card">신분증</option>
                            <option value="resident_record">등본</option>
                            <option value="bankbook">통장사본</option>
                            <option value="income_proof">소득증빙</option>
                            <option value="business_license">사업자등록증</option>
                            <option value="etc" selected>기타</option>
                        </select>
                    </div>
                    <div>
                        <label>안내</label>
                        <div class="mini" style="margin:0;">
                            <div class="tiny">촬영본은 자동으로 최대 1600px / JPEG 압축 후 업로드됩니다.</div>
                        </div>
                    </div>
                </div>

                <div style="margin-top:10px;">
                    <video id="camVideo" autoplay playsinline></video>
                </div>

                <div class="btns">
                    <button type="button" class="btn primary" id="btnStartCam">카메라 시작</button>
                    <button type="button" class="btn" id="btnCapture">촬영</button>
                    <button type="button" class="btn" id="btnStopCam">카메라 종료</button>
                    <button type="button" class="btn primary" id="btnUploadAll">촬영본 업로드</button>
                </div>

                <input type="hidden" id="csrf_token_doc_upload" value="<?= h($_SESSION['csrf_token_doc_upload']) ?>">
                <!-- ✅ index.php upload_notice 호출용 csrf -->
                <input type="hidden" id="csrf_token_index" value="<?= h($_SESSION['csrf_token'] ?? '') ?>">
            </div>

            <div class="card">
                <div class="pill">촬영 목록</div>
                <div id="docList" style="display:grid; gap:10px; margin-top:12px;"></div>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($inquiryId > 0): ?>
        <script>
            (function() {
                const inquiryId = <?= json_encode($inquiryId) ?>;

                const video = document.getElementById('camVideo');
                const btnStartCam = document.getElementById('btnStartCam');
                const btnCapture = document.getElementById('btnCapture');
                const btnStopCam = document.getElementById('btnStopCam');
                const btnUploadAll = document.getElementById('btnUploadAll');
                const docTypeSel = document.getElementById('docType');
                const docList = document.getElementById('docList');

                let stream = null;
                const shots = [];

                function setBtnState() {
                    const camOn = !!stream;
                    btnCapture.disabled = !camOn;
                    btnStopCam.disabled = !camOn;
                }

                async function startCamera() {
                    if (!navigator.mediaDevices?.getUserMedia) {
                        alert('이 브라우저는 카메라 사용을 지원하지 않습니다.');
                        return;
                    }
                    try {
                        stream = await navigator.mediaDevices.getUserMedia({
                            video: {
                                facingMode: {
                                    ideal: 'environment'
                                }
                            },
                            audio: false
                        });
                        video.srcObject = stream;
                        setBtnState();
                    } catch (e) {
                        alert('카메라 권한을 허용해주세요. (HTTPS 필요)');
                    }
                }

                function stopCameraOnly() {
                    if (stream) {
                        stream.getTracks().forEach(t => t.stop());
                        stream = null;
                    }
                    if (video) video.srcObject = null;
                    setBtnState();
                }

                async function capture() {
                    if (!video || !video.videoWidth) {
                        alert('카메라가 준비되지 않았습니다.');
                        return;
                    }

                    const maxW = 1600;
                    const w = video.videoWidth;
                    const h = video.videoHeight;
                    const scale = Math.min(1, maxW / w);
                    const nw = Math.round(w * scale);
                    const nh = Math.round(h * scale);

                    const canvas = document.createElement('canvas');
                    canvas.width = nw;
                    canvas.height = nh;

                    const ctx = canvas.getContext('2d', {
                        alpha: false
                    });
                    ctx.drawImage(video, 0, 0, nw, nh);

                    const blob = await new Promise(res => canvas.toBlob(res, 'image/jpeg', 0.82));
                    if (!blob) {
                        alert('촬영 처리에 실패했습니다.');
                        return;
                    }

                    const idx = shots.length;
                    shots.push(blob);
                    renderShot(blob, idx);
                }

                function renderShot(blob, idx) {
                    const url = URL.createObjectURL(blob);
                    const row = document.createElement('div');
                    row.className = 'mini shot';
                    row.innerHTML = `
      <img src="${url}" alt="촬영본" />
      <div style="min-width:0;">
        <div style="font-weight:900; font-size:13px;">촬영본 #${idx + 1}</div>
        <div class="tiny">${Math.round(blob.size / 1024)} KB</div>
      </div>
      <button type="button" class="btn" data-del="${idx}" style="padding:10px 12px;">삭제</button>
    `;
                    row.querySelector('[data-del]').addEventListener('click', () => {
                        shots[idx] = null;
                        row.remove();
                    });
                    docList.appendChild(row);
                }

                async function markUsed() {
                    const csrfEl = document.getElementById('csrf_token_doc_upload');
                    const csrf = csrfEl?.value || '';

                    const fd = new FormData();
                    fd.append('action', 'mark_used');
                    fd.append('csrf_token', csrf);

                    const res = await fetch('document_upload.php', {
                        method: 'POST',
                        body: fd,
                        credentials: 'same-origin'
                    });

                    const data = await res.json().catch(() => null);
                    if (!data || !data.ok) return false;
                    if (data.csrf_token && csrfEl) csrfEl.value = data.csrf_token;
                    return true;
                }

                // ✅ 업로드 완료 메일 발송 (index.php upload_notice 호출)
                async function notifyUploadToIndex(inquiryId) {
                    try {
                        const csrfIndexEl = document.getElementById('csrf_token_index');
                        const csrfIndex = csrfIndexEl?.value || '';
                        if (!csrfIndex) {
                            console.warn('csrf_token_index is empty');
                            return false;
                        }

                        const fd2 = new FormData();
                        fd2.append('action', 'upload_notice');
                        fd2.append('csrf_token', csrfIndex);
                        fd2.append('inquiry_id', String(inquiryId));

                        const res2 = await fetch('index.php', {
                            method: 'POST',
                            body: fd2,
                            credentials: 'same-origin'
                        });

                        const j2 = await res2.json().catch(() => null);
                        if (!j2 || !j2.ok) {
                            console.warn('upload_notice failed:', j2);
                            return false;
                        }
                        return true;
                    } catch (e) {
                        console.warn('upload_notice exception', e);
                        return false;
                    }
                }

                async function uploadAll() {
                    const valid = shots.filter(Boolean);
                    if (valid.length === 0) {
                        alert('업로드할 촬영본이 없습니다.');
                        return;
                    }

                    const fd = new FormData();
                    fd.append('inquiry_id', String(inquiryId));
                    fd.append('doc_type', (docTypeSel?.value || 'etc'));
                    valid.forEach((b, i) => fd.append('files[]', b, `camera_${Date.now()}_${i}.jpg`));

                    btnUploadAll.disabled = true;

                    try {
                        const res = await fetch('upload_document.php', {
                            method: 'POST',
                            body: fd,
                            credentials: 'same-origin'
                        });

                        const data = await res.json().catch(() => null);

                        if (!data || !data.ok) {
                            console.error('UPLOAD_FAIL', {
                                status: res.status,
                                data
                            });
                            alert((data && data.message) ? data.message : '업로드에 실패했습니다.');
                            return;
                        }

                        await markUsed();

                        // ✅ 업로드 성공 직후 index.php(upload_notice)도 호출 (메일 발송 트리거)
                        await notifyUploadToIndex(inquiryId);

                        // 디버그(메일 실패 시 콘솔 로그) - upload_document.php에서 직접 메일도 보내는 경우를 대비
                        if (data.data && data.data.mail && data.data.mail.ok === false) {
                            console.warn('MAIL_FAIL', data.data.mail);
                        }

                        alert('서류 업로드 완료!');
                        shots.length = 0;
                        docList.innerHTML = '';
                    } catch (e) {
                        alert('네트워크 오류가 발생했습니다.');
                    } finally {
                        btnUploadAll.disabled = false;
                    }
                }

                btnStartCam?.addEventListener('click', startCamera);
                btnCapture?.addEventListener('click', capture);
                btnStopCam?.addEventListener('click', () => {
                    stopCameraOnly();
                    location.href = 'index.php#apply';
                });
                btnUploadAll?.addEventListener('click', uploadAll);

                setBtnState();
                window.addEventListener('beforeunload', stopCameraOnly);
            })();
        </script>
    <?php endif; ?>
</body>

</html>