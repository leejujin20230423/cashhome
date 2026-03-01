<?php
declare(strict_types=1);

namespace Cashhome\Storage;

require_once __DIR__ . '/StorageAdapterInterface.php';

final class LocalStorageAdapter implements StorageAdapterInterface
{
    private string $baseDir;
    private string $publicBaseUrl;

    public function __construct(string $baseDir, string $publicBaseUrl)
    {
        $this->baseDir = rtrim($baseDir, '/');
        $this->publicBaseUrl = rtrim($publicBaseUrl, '/');
    }

    /**
     * StorageAdapterInterface 구현
     * @param string $relativePath 예: docs/123/abcdef.jpg
     * @param string $binary 파일 바이너리
     * @param string $mime mime type (로컬 저장에서는 주로 참고용)
     * @return string 실제 저장된 relativePath
     */
    public function put(string $relativePath, string $binary, string $mime): string
    {
        $relativePath = ltrim($relativePath, '/');
        $relativePath = str_replace(['..\\', '../', '\\'], ['', '', '/'], $relativePath);

        $dest = $this->baseDir . '/' . $relativePath;
        $dir = dirname($dest);

        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0775, true) && !is_dir($dir)) {
                throw new \RuntimeException('업로드 폴더 생성 실패: ' . $dir);
            }
        }
        if (!is_writable($dir)) {
            $perms = @fileperms($dir);
            throw new \RuntimeException(
                '업로드 폴더 쓰기 불가: ' . $dir . ' perms=' . ($perms ? substr(sprintf('%o', $perms), -4) : 'unknown')
            );
        }

        $bytes = @file_put_contents($dest, $binary);
        if ($bytes === false) {
            $last = error_get_last();
            throw new \RuntimeException('파일 저장 실패: ' . ($last['message'] ?? 'unknown'));
        }

        @chmod($dest, 0664);

        return $relativePath;
    }

    /**
     * StorageAdapterInterface 구현
     */
    public function publicUrl(string $relativePath): string
    {
        $relativePath = ltrim($relativePath, '/');
        return $this->publicBaseUrl . '/' . $relativePath;
    }

    /**
     * (옵션) 기존 코드 호환용: $_FILES 한 건을 받아 저장하고 URL 등 반환
     * DocumentUploader에서는 안 쓰지만, 필요하면 유지 가능
     */
    public function saveUploadedFile(array $file, string $relativeDir = '', string $saveName = ''): array
    {
        $tmp = (string)($file['tmp_name'] ?? '');
        if ($tmp === '' || !is_uploaded_file($tmp)) {
            throw new \RuntimeException('업로드 임시파일이 유효하지 않습니다.');
        }

        $relativeDir = trim($relativeDir, '/');

        if ($saveName === '') {
            $ext = $this->guessExt((string)($file['name'] ?? ''), (string)($file['type'] ?? ''));
            $saveName = 'doc_' . date('Ymd_His') . '_' . bin2hex(random_bytes(6)) . $ext;
        } else {
            $saveName = preg_replace('/[^a-zA-Z0-9._-]/', '_', $saveName) ?? $saveName;
        }

        $binary = (string)file_get_contents($tmp);

        $relativePath = ($relativeDir !== '' ? $relativeDir . '/' : '') . $saveName;
        $savedPath = $this->put($relativePath, $binary, (string)($file['type'] ?? 'application/octet-stream'));

        $dest = $this->baseDir . '/' . $savedPath;

        return [
            'path' => 'uploads/' . $savedPath,
            'url'  => $this->publicUrl($savedPath),
            'size' => (int)filesize($dest),
        ];
    }

    private function guessExt(string $originalName, string $mime): string
    {
        $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        if ($ext !== '') return '.' . $ext;

        return match ($mime) {
            'image/jpeg' => '.jpg',
            'image/png'  => '.png',
            'application/pdf' => '.pdf',
            default => '.bin'
        };
    }
}