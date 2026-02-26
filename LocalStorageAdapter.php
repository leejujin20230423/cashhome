<?php
declare(strict_types=1);

final class LocalStorageAdapter
{
    private string $baseDir;
    private string $publicBaseUrl;

    public function __construct(string $baseDir, string $publicBaseUrl)
    {
        $this->baseDir = rtrim($baseDir, '/');
        $this->publicBaseUrl = rtrim($publicBaseUrl, '/');
    }

    /**
     * 업로드된 파일을 저장하고 public URL을 리턴
     *
     * @param array $file  $_FILES에서 꺼낸 1개 파일 배열 (name,type,tmp_name,error,size)
     * @param string $relativeDir 예: '16/id_card' 같은 서브폴더 (없으면 '' 가능)
     * @param string $saveName 저장 파일명(확장자 포함) (없으면 자동 생성)
     * @return array ['path' => 'uploads/..', 'url' => 'https://..', 'size' => int]
     */
    public function saveUploadedFile(array $file, string $relativeDir = '', string $saveName = ''): array
    {
        $tmp = (string)($file['tmp_name'] ?? '');
        if ($tmp === '' || !is_uploaded_file($tmp)) {
            throw new RuntimeException('업로드 임시파일이 유효하지 않습니다.');
        }

        // 디렉토리 준비
        $relativeDir = trim($relativeDir, '/');
        $targetDir = $this->baseDir . ($relativeDir !== '' ? '/' . $relativeDir : '');

        if (!is_dir($targetDir)) {
            if (!@mkdir($targetDir, 0775, true) && !is_dir($targetDir)) {
                throw new RuntimeException('업로드 폴더 생성 실패: ' . $targetDir);
            }
        }
        if (!is_writable($targetDir)) {
            $perms = @fileperms($targetDir);
            throw new RuntimeException('업로드 폴더 쓰기 불가: ' . $targetDir . ' perms=' . ($perms ? substr(sprintf('%o', $perms), -4) : 'unknown'));
        }

        // 파일명 생성
        if ($saveName === '') {
            $ext = $this->guessExt((string)($file['name'] ?? ''), (string)($file['type'] ?? ''));
            $saveName = 'doc_' . date('Ymd_His') . '_' . bin2hex(random_bytes(6)) . $ext;
        } else {
            // 파일명 안전화
            $saveName = preg_replace('/[^a-zA-Z0-9._-]/', '_', $saveName) ?? $saveName;
        }

        $dest = $targetDir . '/' . $saveName;

        // ✅ 핵심: rename() 말고 move_uploaded_file() 사용
        if (!@move_uploaded_file($tmp, $dest)) {
            // move 실패 시 copy fallback (서버마다 move가 막히는 경우 대비)
            $copied = @copy($tmp, $dest);
            if (!$copied) {
                $last = error_get_last();
                throw new RuntimeException('파일 저장 실패: ' . ($last['message'] ?? 'unknown'));
            }
        }

        @chmod($dest, 0664);

        $publicPath = 'uploads' . ($relativeDir !== '' ? '/' . $relativeDir : '') . '/' . $saveName;
        $url = $this->publicBaseUrl . '/' . ($relativeDir !== '' ? $relativeDir . '/' : '') . $saveName;

        return [
            'path' => $publicPath,
            'url'  => $url,
            'size' => (int)filesize($dest),
        ];
    }

    private function guessExt(string $originalName, string $mime): string
    {
        $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        if ($ext !== '') return '.' . $ext;

        // mime 기반 fallback
        return match ($mime) {
            'image/jpeg' => '.jpg',
            'image/png'  => '.png',
            'application/pdf' => '.pdf',
            default => '.bin'
        };
    }
}