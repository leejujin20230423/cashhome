<?php
declare(strict_types=1);

namespace Cashhome;

use Cashhome\Storage\StorageAdapterInterface;

require_once __DIR__ . '/Storage/StorageAdapterInterface.php';

final class DocumentUploader
{
    public function __construct(
        private \PDO $pdo,
        private StorageAdapterInterface $storage,
        private int $maxWidth = 1600,
        private int $jpegQuality = 82
    ) {}

    public function handleUploadedFile(
        int $inquiryId,
        array $file,
        string $docType = 'etc',
        int $sort = 1
    ): array
    {
        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            throw new \RuntimeException('업로드 오류');
        }

        $tmp = (string)($file['tmp_name'] ?? '');
        $origName = (string)($file['name'] ?? 'camera.jpg');

        $finfo = new \finfo(\FILEINFO_MIME_TYPE);
        $mime = (string)($finfo->file($tmp) ?: '');

        if (!in_array($mime, ['image/jpeg', 'image/png', 'image/webp'], true)) {
            throw new \RuntimeException('허용되지 않은 이미지 형식');
        }

        [$w, $h] = @getimagesize($tmp) ?: [0, 0];
        if ($w < 1 || $h < 1) {
            throw new \RuntimeException('이미지 크기 확인 실패');
        }

        $src = match ($mime) {
            'image/jpeg' => @imagecreatefromjpeg($tmp),
            'image/png'  => @imagecreatefrompng($tmp),
            'image/webp' => @imagecreatefromwebp($tmp),
            default => null,
        };

        if (!$src) {
            throw new \RuntimeException('이미지 로드 실패');
        }

        $scale = min(1, $this->maxWidth / $w);
        $nw = (int)round($w * $scale);
        $nh = (int)round($h * $scale);

        $dst = imagecreatetruecolor($nw, $nh);
        imagecopyresampled($dst, $src, 0, 0, 0, 0, $nw, $nh, $w, $h);

        ob_start();
        imagejpeg($dst, null, $this->jpegQuality);
        $binary = (string)ob_get_clean();

        imagedestroy($src);
        imagedestroy($dst);

        $filename = bin2hex(random_bytes(16)) . '.jpg';
        $relativePath = "docs/{$inquiryId}/{$filename}";

        $savedPath = $this->storage->put($relativePath, $binary, 'image/jpeg');
        $sizeBytes = strlen($binary);

        $stmt = $this->pdo->prepare("
            INSERT INTO cashhome_1200_documents (
                cashhome_1200_inquiry_id,
                cashhome_1200_doc_type,
                cashhome_1200_sort,
                cashhome_1200_file_path,
                cashhome_1200_original_name,
                cashhome_1200_mime,
                cashhome_1200_size_bytes,
                cashhome_1200_width,
                cashhome_1200_height
            ) VALUES (
                :iid, :doc_type, :sort, :path, :orig, :mime, :size, :w, :h
            )
        ");

        $stmt->execute([
            ':iid' => $inquiryId,
            ':doc_type' => $docType,
            ':sort' => $sort,
            ':path' => '/uploads/' . $savedPath,
            ':orig' => mb_substr($origName, 0, 255),
            ':mime' => 'image/jpeg',
            ':size' => $sizeBytes,
            ':w' => $nw,
            ':h' => $nh,
        ]);

        $id = (int)$this->pdo->lastInsertId();

        return [
            'doc_id' => $id,
            'url' => $this->storage->publicUrl($savedPath),
            'size' => $sizeBytes,
            'width' => $nw,
            'height' => $nh,
        ];
    }
}