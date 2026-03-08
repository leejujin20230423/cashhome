<?php
declare(strict_types=1);

namespace Cashhome\Storage;

require_once __DIR__ . '/StorageAdapterInterface.php';

final class LocalStorageAdapter implements StorageAdapterInterface
{
    public function __construct(
        private string $baseDir,      // 실제 디스크 저장 경로
        private string $publicBaseUrl // 공개 접근 URL
    ) {}

    public function put(string $relativePath, string $binary, string $mime): string
    {
        $fullPath = rtrim($this->baseDir, '/').'/'.ltrim($relativePath, '/');

        $dir = dirname($fullPath);
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0775, true) && !is_dir($dir)) {
                throw new \RuntimeException('업로드 디렉토리 생성 실패');
            }
        }

        if (!is_writable($dir)) {
            @chmod($dir, 0775);
        }
        if (!is_writable($dir)) {
            @chmod($dir, 0777);
        }
        if (!is_writable($dir)) {
            $perms = @fileperms($dir);
            $permTxt = $perms ? substr(sprintf('%o', $perms), -4) : 'unknown';
            throw new \RuntimeException('업로드 폴더 쓰기 불가: ' . $dir . ' perms=' . $permTxt);
        }

        // 일부 스토리지에서 LOCK_EX가 실패할 수 있어 일반 write로 1회 재시도
        $bytes = @file_put_contents($fullPath, $binary, LOCK_EX);
        if ($bytes === false) {
            $bytes = @file_put_contents($fullPath, $binary);
        }
        if ($bytes === false) {
            $last = error_get_last();
            $reason = (string)($last['message'] ?? 'unknown');
            throw new \RuntimeException('파일 저장 실패: ' . $fullPath . ' / ' . $reason);
        }

        return $relativePath;
    }

    public function publicUrl(string $relativePath): string
    {
        return rtrim($this->publicBaseUrl, '/').'/'.ltrim($relativePath, '/');
    }
}
