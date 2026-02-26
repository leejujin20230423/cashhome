<?php
declare(strict_types=1);

/**
 * admin_document_upload.php
 * - 관리자(로그인) 전용: "서류추가"(관리자 추가 서류) 촬영/업로드 화면
 * - 업로드 완료 시 자동으로 admin_inquiries.php(첫페이지/리스트)로 이동
 */

session_start();

header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

const ADMIN_SESSION_TTL = 7200;

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function is_admin_authed(): bool {
    if (empty($_SESSION['cashhome_admin_authed']) || empty($_SESSION['cashhome_admin_authed_at'])) return false;
    if ((time() - (int)$_SESSION['cashhome_admin_authed_at']) > ADMIN_SESSION_TTL) return false;
    return true;
}

if (!is_admin_authed()) {
    http_response_code(403);
    echo 'Forbidden';
    exit;
}

$inquiryId = (int)($_GET['inquiry_id'] ?? 0);
if ($inquiryId <= 0) {
    http_response_code(400);
    echo 'Bad Request';
    exit;
}

if (empty($_SESSION['csrf_token_admin_upload'])) {
    $_SESSION['csrf_token_admin_upload'] = bin2hex(random_bytes(32));
}

$csrf = (string)$_SESSION['csrf_token_admin_upload'];
?>
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow" />
  <title>관리자 서류추가</title>
  <style>
    :root{--bg:#0b1220;--card:#0f172a;--text:#e5e7eb;--muted:#94a3b8;--line:rgba(148,163,184,.18);--btn:#2563eb;--btn2:#334155}
    *{box-sizing:border-box}
    body{margin:0;background:linear-gradient(180deg,#0b1220,#060a12);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,'Noto Sans KR',sans-serif}
    .wrap{max-width:760px;margin:0 auto;padding:18px}
    .card{background:rgba(15,23,42,.85);border:1px solid var(--line);border-radius:14px;padding:14px;box-shadow:0 12px 30px rgba(0,0,0,.25)}
    h1{font-size:18px;margin:0 0 10px}
    .hint{color:var(--muted);font-size:12px;line-height:1.5}
    .row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
    .btn{appearance:none;border:0;border-radius:10px;padding:10px 12px;font-weight:700;cursor:pointer;color:white;background:var(--btn)}
    .btn.secondary{background:var(--btn2)}
    .btn:disabled{opacity:.5;cursor:not-allowed}
    .videoBox{margin-top:12px;border:1px solid var(--line);border-radius:14px;overflow:hidden;background:#020617}
    video,canvas,img{display:block;width:100%;height:auto}
    .thumbs{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:12px}
    .thumb{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#020617;position:relative}
    .thumb img{width:100%;display:block}
    .thumb .x{position:absolute;top:6px;right:6px;background:rgba(0,0,0,.55);border:1px solid rgba(255,255,255,.15);color:#fff;border-radius:8px;padding:4px 6px;font-size:12px;cursor:pointer}
    .msg{margin-top:10px;font-size:12px;color:var(--muted)}
    .bar{display:flex;justify-content:space-between;align-items:center;margin-top:12px;gap:10px;flex-wrap:wrap}
    .pill{font-size:12px;border:1px solid var(--line);border-radius:999px;padding:6px 10px;color:var(--muted)}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>관리자 서류추가 (접수 #<?= h((string)$inquiryId) ?>)</h1>
      <div class="hint">카메라로 촬영 후 업로드하면 <b>관리자 추가 서류</b>로 등록됩니다. 업로드 완료 후 자동으로 리스트 화면으로 돌아갑니다.</div>

      <div class="videoBox">
        <video id="video" playsinline autoplay muted></video>
      </div>
      <canvas id="canvas" hidden></canvas>

      <div class="row">
        <button class="btn" id="startBtn" type="button">카메라 시작</button>
        <button class="btn secondary" id="shotBtn" type="button" disabled>촬영</button>
        <button class="btn" id="uploadBtn" type="button" disabled>업로드</button>
        <a class="btn secondary" href="admin_inquiries.php?id=<?= h((string)$inquiryId) ?>" style="text-decoration:none;display:inline-flex;align-items:center;">뒤로</a>
      </div>

      <div class="bar">
        <div class="pill">촬영본: <span id="count">0</span>장</div>
        <div class="pill">유형: 관리자 추가 서류</div>
      </div>

      <div class="thumbs" id="thumbs"></div>

      <div class="msg" id="msg"></div>
    </div>
  </div>

<script>
(() => {
  const inquiryId = <?= (int)$inquiryId ?>;
  const csrf = <?= json_encode($csrf, JSON_UNESCAPED_UNICODE) ?>;

  const video = document.getElementById('video');
  const canvas = document.getElementById('canvas');
  const startBtn = document.getElementById('startBtn');
  const shotBtn = document.getElementById('shotBtn');
  const uploadBtn = document.getElementById('uploadBtn');
  const thumbs = document.getElementById('thumbs');
  const countEl = document.getElementById('count');
  const msg = document.getElementById('msg');

  let stream = null;
  /** @type {Blob[]} */
  const shots = [];

  function setMsg(t){ msg.textContent = t || ''; }

  function refreshThumbs(){
    thumbs.innerHTML = '';
    countEl.textContent = String(shots.length);
    uploadBtn.disabled = shots.length === 0;
    shots.forEach((b, idx) => {
      const url = URL.createObjectURL(b);
      const div = document.createElement('div');
      div.className = 'thumb';
      div.innerHTML = `<img src="${url}" alt="shot ${idx+1}"><button type="button" class="x">삭제</button>`;
      div.querySelector('.x').addEventListener('click', () => {
        shots.splice(idx, 1);
        refreshThumbs();
      });
      thumbs.appendChild(div);
    });
  }

  async function startCamera(){
    setMsg('');
    if (stream) return;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
      video.srcObject = stream;
      shotBtn.disabled = false;
      startBtn.disabled = true;
    } catch (e) {
      setMsg('카메라를 사용할 수 없습니다. 브라우저 권한을 확인해주세요.');
      console.error(e);
    }
  }

  async function takeShot(){
    if (!stream) return;
    const w = video.videoWidth || 1280;
    const h = video.videoHeight || 720;
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(video, 0, 0, w, h);
    const blob = await new Promise(res => canvas.toBlob(res, 'image/jpeg', 0.9));
    if (!blob) return;
    shots.push(blob);
    refreshThumbs();
  }

  async function upload(){
    if (shots.length === 0) return;
    uploadBtn.disabled = true;
    shotBtn.disabled = true;
    setMsg('업로드 중...');
    try {
      const fd = new FormData();
      fd.append('csrf_token', csrf);
      fd.append('inquiry_id', String(inquiryId));
      shots.forEach((b, i) => fd.append('files[]', b, `admin_extra_${i+1}.jpg`));
      const res = await fetch('admin_upload_document.php', { method: 'POST', body: fd, credentials: 'same-origin' });
      const data = await res.json().catch(() => null);
      if (!data || !data.ok) {
        throw new Error((data && data.message) ? data.message : '업로드 실패');
      }
      setMsg('업로드 완료! 리스트로 이동합니다...');
      setTimeout(() => {
        location.href = '/';
      }, 400);
    } catch (e) {
      console.error(e);
      setMsg(String(e && e.message ? e.message : e));
      uploadBtn.disabled = false;
      shotBtn.disabled = false;
    }
  }

  startBtn.addEventListener('click', startCamera);
  shotBtn.addEventListener('click', takeShot);
  uploadBtn.addEventListener('click', upload);

  // 자동 시작 시도(모바일 UX)
  startCamera();
})();
</script>
</body>
</html>
