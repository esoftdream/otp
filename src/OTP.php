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
     * @var int ID user
     */
    private int $userId;

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
     * Constructor
     * 
     * @param string $userType 'admin' atau 'member'
     * @param int $userId ID dari admin/member
     * @param BaseConnection|null $db Koneksi database opsional (untuk testing)
     */
    public function __construct(string $userType, int $userId, ?BaseConnection $db = null)
    {
        $this->db = $db ?? Database::connect();
        $this->userType = $userType;
        $this->userId = $userId;
    }

    /**
     * Set masa berlaku OTP
     */
    public function setExpiry(int $minutes): self
    {
        $this->expiryMinutes = $minutes;
        return $this;
    }

    /**
     * Set panjang kode OTP
     */
    public function setLength(int $length): self
    {
        $this->otpLength = $length;
        return $this;
    }

    /**
     * Generate kode OTP baru
     * 
     * @return array ['otp' => string, 'expired' => string]
     * @throws RuntimeException Jika tipe OTP belum diset
     */
    public function generate(): array
    {
        if (empty($this->type)) {
            throw new RuntimeException('OTP type belum diset');
        }

        // Generate kode acak
        $max     = pow(10, $this->otpLength) - 1;
        $otpCode = str_pad((string) random_int(0, $max), $this->otpLength, '0', STR_PAD_LEFT);

        // Gunakan UTC untuk konsistensi di database
        $now = Time::now('UTC');
        $expiredAt = $now->addMinutes($this->expiryMinutes);

        if ($this->saveToDatabase($otpCode, $expiredAt)) {
            return [
                'otp'     => $otpCode,
                'expired' => $expiredAt->toDateTimeString(),
            ];
        }

        return [];
    }

    /**
     * Menyimpan OTP ke database dan menghapus OTP lama yang belum terpakai
     */
    private function saveToDatabase(string $otpCode, Time $expiredAt): bool
    {
        $now = Time::now('UTC')->toDateTimeString();

        // Bersihkan OTP lama yang belum digunakan untuk user & tipe yang sama
        $this->db->table('log_otp')->where([
            'otp_user_id'       => $this->userId,
            'otp_user_type'     => $this->userType,
            'otp_type'          => $this->type,
            'otp_used_datetime' => null,
        ])->delete();

        return $this->db->table('log_otp')->insert([
            'otp_user_id'          => $this->userId,
            'otp_user_type'        => $this->userType,
            'otp_type'             => $this->type,
            'otp_value'            => password_hash($otpCode, PASSWORD_BCRYPT),
            'otp_expired_datetime' => $expiredAt->toDateTimeString(),
            'otp_created_datetime' => $now,
            'otp_updated_datetime' => $now,
        ]);
    }

    /**
     * Verifikasi kode OTP
     * 
     * @param string $otpInput Kode OTP yang diinput user
     * @return bool True jika valid
     * @throws Exception Berbagai pesan error jika tidak valid
     */
    public function verify(string $otpInput): bool
    {
        if (empty($this->type)) {
            throw new RuntimeException('OTP type belum diset');
        }

        // 1. Normalisasi Input: Hanya ambil angka dan pad jika perlu
        $otpInput = preg_replace('/[^0-9]/', '', $otpInput);
        $otpInput = str_pad($otpInput, $this->otpLength, '0', STR_PAD_LEFT);

        // 2. Ambil data OTP terbaru
        $data = $this->db->table('log_otp')
            ->where([
                'otp_user_id'   => $this->userId,
                'otp_user_type' => $this->userType,
                'otp_type'      => $this->type,
            ])
            ->orderBy('otp_id', 'DESC')
            ->limit(1)
            ->get()
            ->getRow();

        if (! $data) {
            throw new Exception('Kode OTP tidak ditemukan');
        }

        // 3. Cek Status Penggunaan
        if ($data->otp_used_datetime !== null) {
            throw new Exception('Kode OTP sudah digunakan');
        }

        // 4. Cek Validitas Kode (Hashing)
        if (! password_verify($otpInput, $data->otp_value)) {
            throw new Exception('Kode OTP tidak valid');
        }

        // 5. Cek Kedaluwarsa (Gunakan UTC untuk perbandingan)
        $expiredAt = Time::parse($data->otp_expired_datetime, 'UTC');
        if (Time::now('UTC')->isAfter($expiredAt)) {
            throw new Exception('Kode OTP sudah kedaluwarsa');
        }

        // 6. Tandai Terpakai
        return $this->markAsUsed($data->otp_id);
    }

    /**
     * Tandai OTP sebagai telah digunakan
     */
    private function markAsUsed(int $otpId): bool
    {
        $now = Time::now('UTC')->toDateTimeString();

        return $this->db->table('log_otp')
            ->where('otp_id', $otpId)
            ->update([
                'otp_used_datetime'    => $now,
                'otp_updated_datetime' => $now,
            ]);
    }
}
