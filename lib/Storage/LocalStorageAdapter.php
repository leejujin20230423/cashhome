<?php
declare(strict_types=1);

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
                throw new RuntimeException('업로드 디렉토리 생성 실패');
            }
        }

        if (file_put_contents($fullPath, $binary, LOCK_EX) === false) {
            throw new RuntimeException('파일 저장 실패');
        }

        return $relativePath;
    }

    public function publicUrl(string $relativePath): string
    {
        return rtrim($this->publicBaseUrl, '/').'/'.ltrim($relativePath, '/');
    }
}