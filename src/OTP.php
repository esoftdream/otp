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

        // Gunakan Asia/Jakarta untuk konsistensi di database
        $now = Time::now('Asia/Jakarta');
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
     * Menyimpan OTP ke database
     */
    private function saveToDatabase(string $otpCode, Time $expiredAt): bool
    {
        $now = Time::now('Asia/Jakarta')->toDateTimeString();

        // Catatan: Kita tidak menghapus OTP lama di sini agar lebih resilien 
        // jika ada delay pengiriman atau klik ganda oleh user.

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

        // 2. Ambil SEMUA OTP yang belum digunakan untuk user & tipe ini
        // Menggunakan limit 10 untuk keamanan dan performa (user tidak boleh punya terlalu banyak OTP aktif)
        $otpRecords = $this->db->table('log_otp')
            ->where([
                'otp_user_id'       => $this->userId,
                'otp_user_type'     => $this->userType,
                'otp_type'          => $this->type,
                'otp_used_datetime' => null,
            ])
            ->orderBy('otp_id', 'DESC')
            ->limit(10)
            ->get()
            ->getResult();

        if (empty($otpRecords)) {
            throw new Exception('Kode OTP tidak ditemukan atau sudah digunakan');
        }

        $now = Time::now('Asia/Jakarta');

        // 3. Iterasi melalui semua kode aktif untuk mencari yang cocok
        foreach ($otpRecords as $data) {
            // Cek Validitas Kode (Hashing)
            if (password_verify($otpInput, $data->otp_value)) {
                
                // Cek Kedaluwarsa untuk record yang cocok ini
                $expiredAt = Time::parse($data->otp_expired_datetime, 'Asia/Jakarta');
                if ($now->isAfter($expiredAt)) {
                    throw new Exception('Kode OTP sudah kedaluwarsa');
                }

                // 4. Jika valid, tandai hanya record ini sebagai terpakai
                return $this->markAsUsed($data->otp_id);
            }
        }

        throw new Exception('Kode OTP tidak valid');
    }

    /**
     * Tandai OTP sebagai telah digunakan
     */
    private function markAsUsed(int $otpId): bool
    {
        $now = Time::now('Asia/Jakarta')->toDateTimeString();

        return $this->db->table('log_otp')
            ->where('otp_id', $otpId)
            ->update([
                'otp_used_datetime'    => $now,
                'otp_updated_datetime' => $now,
            ]);
    }
}
