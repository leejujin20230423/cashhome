<?php
declare(strict_types=1);

namespace Cashhome\Storage;

interface StorageAdapterInterface
{
    /**
     * 파일 저장
     * @param string $relativePath 예: docs/123/abcdef.jpg
     * @param string $binary 파일 바이너리
     * @param string $mime mime type
     * @return string 실제 저장된 relativePath
     */
    public function put(string $relativePath, string $binary, string $mime): string;

    /**
     * 공개 접근 URL 반환
     */
    public function publicUrl(string $relativePath): string;
}