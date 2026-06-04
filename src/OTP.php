<?php

namespace Esoftdream\OTP;

use CodeIgniter\Database\BaseConnection;
use CodeIgniter\I18n\Time;
use Config\Database;
use Exception;
use RuntimeException;

/**
 * Class OTP
 * Menangani pembuatan dan verifikasi One-Time Password (OTP)
 */
class OTP
{
    /**
     * @var string Tipe OTP (contoh: 'forgot', 'login', 'transfer')
     */
    public string $type = '';

    /**
     * @var string Tipe user ('admin' atau 'member')
     */
    private string $userType;

    /**
     * @var int|null ID user
     */
    private ?int $userId = null;

    /**
     * @var string|null Identifier (email/telepon/session) jika userId tidak ada
     */
    private ?string $identifier = null;

    /**
     * @var int Masa berlaku OTP dalam menit
     */
    protected int $expiryMinutes = 10;

    /**
     * @var int Panjang kode OTP
     */
    protected int $otpLength = 6;

    /**
     * @var BaseConnection Koneksi database
     */
    private BaseConnection $db;

    /**
     * 🔑 Single source of truth timezone
     */
    private string $tz = 'Asia/Jakarta';

    public function __construct(
        string $userType,
        ?int $userId = null,
        ?BaseConnection $db = null,
        ?string $identifier = null
    ) {
        $this->db = $db ?? Database::connect();
        $this->userType = $userType;
        $this->userId = $userId;
        $this->identifier = $identifier;

        if ($this->userId === null && empty($this->identifier)) {
            throw new \InvalidArgumentException('User ID atau Identifier harus diisi salah satu.');
        }
    }

    public function setExpiry(int $minutes): self
    {
        $this->expiryMinutes = $minutes;
        return $this;
    }

    public function setLength(int $length): self
    {
        $this->otpLength = $length;
        return $this;
    }

    public function generate(): array
    {
        if (empty($this->type)) {
            throw new RuntimeException('OTP type belum diset');
        }

        // Generate kode acak
        $max     = pow(10, $this->otpLength) - 1;
        $otpCode = str_pad((string) random_int(0, $max), $this->otpLength, '0', STR_PAD_LEFT);

        // ✅ Konsisten Asia/Jakarta
        $now = Time::now($this->tz);
        $expiredAt = $now->addMinutes($this->expiryMinutes);

        if ($this->saveToDatabase($otpCode, $now, $expiredAt)) {
            return [
                'otp'     => $otpCode,
                'expired' => $expiredAt->toDateTimeString(),
            ];
        }

        return [];
    }

    private function saveToDatabase(string $otpCode, Time $now, Time $expiredAt): bool
    {
        // Catatan: Kita tidak menghapus OTP lama di sini agar lebih resilien 
        // jika ada delay pengiriman atau klik ganda oleh user.

        return $this->db->table('log_otp')->insert([
            'otp_user_id'          => $this->userId,
            'otp_identifier'       => $this->identifier,
            'otp_user_type'        => $this->userType,
            'otp_type'             => $this->type,
            'otp_value'            => password_hash($otpCode, PASSWORD_BCRYPT),
            'otp_expired_datetime' => $expiredAt->toDateTimeString(),
            'otp_created_datetime' => $now->toDateTimeString(),
            'otp_updated_datetime' => $now->toDateTimeString(),
        ]);
    }

    public function verify(string $otpInput): bool
    {
        if (empty($this->type)) {
            throw new RuntimeException('OTP type belum diset');
        }

        // 1. Normalisasi Input
        $otpInput = preg_replace('/[^0-9]/', '', $otpInput);
        $otpInput = str_pad($otpInput, $this->otpLength, '0', STR_PAD_LEFT);

        // 2. Ambil OTP aktif
        $where = [
            'otp_user_type'     => $this->userType,
            'otp_type'          => $this->type,
            'otp_used_datetime' => null,
        ];

        if ($this->userId !== null) {
            $where['otp_user_id'] = $this->userId;
        } else {
            $where['otp_identifier'] = $this->identifier;
        }

        $otpRecords = $this->db->table('log_otp')
            ->where($where)
            ->orderBy('otp_id', 'DESC')
            ->limit(10)
            ->get()
            ->getResult();

        if (empty($otpRecords)) {
            throw new Exception('Kode OTP tidak ditemukan atau sudah digunakan');
        }

        // ✅ Konsisten Asia/Jakarta
        $now = Time::now($this->tz);

        foreach ($otpRecords as $data) {
            if (password_verify($otpInput, $data->otp_value)) {

                // ✅ Parse dengan timezone yang sama
                $expiredAt = Time::parse($data->otp_expired_datetime, $this->tz);

                if ($now->isAfter($expiredAt)) {
                    throw new Exception('Kode OTP sudah kedaluwarsa');
                }

                return $this->markAsUsed($data->otp_id);
            }
        }

        throw new Exception('Kode OTP tidak valid');
    }

    private function markAsUsed(int $otpId): bool
    {
        $now = Time::now($this->tz);

        return $this->db->table('log_otp')
            ->where('otp_id', $otpId)
            ->update([
                'otp_used_datetime'    => $now->toDateTimeString(),
                'otp_updated_datetime' => $now->toDateTimeString(),
            ]);
    }
}
