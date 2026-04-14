<?php

namespace Esoftdream\OTP;

use CodeIgniter\Database\BaseConnection;
use CodeIgniter\I18n\Time;
use Config\Database;
use Exception;
use RuntimeException;

class OTP
{
    /**
     * @var string Tipe OTP. isi: 'pin','bonus','forgot','profile','change_password', 'transfer'
     */
    public string $type;

    /**
     * @var string Tipe user. admin / member
     */
    private string $userType;

    /**
     * @var int ID admin/member
     */
    private int $userID;

    /**
     * @var int Masa berlaku OTP dalam menit
     */
    protected int $expiryMinutes = 10;

    /**
     * @var int Panjang kode OTP
     */
    protected int $otpLength = 6;

    private BaseConnection $db;

    public function __construct(string $userType, int $userID, ?BaseConnection $db = null)
    {
        $this->db = $db ?? Database::connect();

        $this->userType = $userType;
        $this->userID   = $userID;
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
     * Generate kode OTP
     *
     * @return array Berisi kode otp & waktu kadaluarsa
     */
    public function generate(): array
    {
        if (empty($this->type)) {
            throw new RuntimeException('OTP type belum diset');
        }

        $now        = Time::now();
        $max        = pow(10, $this->otpLength) - 1;
        $OTPCode    = str_pad((string) random_int(0, $max), $this->otpLength, '0', STR_PAD_LEFT);
        $OTPExpired = $now->addMinutes($this->expiryMinutes)->toDateTimeString();

        $save = $this->save($OTPCode, $OTPExpired);

        if ($save) {
            return [
                'otp'     => $OTPCode,
                'expired' => $OTPExpired,
            ];
        }

        return [];
    }

    /**
     * Insert kode OTP ke database
     * Kode OTP lama yang belum digunakan akan dihapus
     */
    private function save(string $OTPCode, string $OTPExpired): bool
    {
        $builder = $this->db->table('log_otp');
        $now     = Time::now()->toDateTimeString();

        // Hapus OTP lama yang belum digunakan untuk user & tipe ini
        $builder->where([
            'otp_type'          => $this->type,
            'otp_user_type'     => $this->userType,
            'otp_user_id'       => $this->userID,
            'otp_used_datetime' => null,
        ])->delete();

        return $builder->insert([
            'otp_user_id'          => $this->userID,
            'otp_user_type'        => $this->userType,
            'otp_type'             => $this->type,
            'otp_value'            => password_hash($OTPCode, PASSWORD_DEFAULT),
            'otp_expired_datetime' => $OTPExpired,
            'otp_updated_datetime' => $now,
            'otp_created_datetime' => $now,
        ]);
    }

    /**
     * Proses verifikasi OTP
     */
    public function verify(string $OTPCode): bool
    {
        if (empty($this->type)) {
            throw new RuntimeException('OTP type belum diset');
        }

        $OTPCode = trim($OTPCode);
        if (is_numeric($OTPCode)) {
            $OTPCode = str_pad($OTPCode, $this->otpLength, '0', STR_PAD_LEFT);
        }

        $data = $this->db->table('log_otp')
            ->select('otp_id, otp_expired_datetime, otp_value, otp_used_datetime')
            ->where([
                'otp_user_id'   => $this->userID,
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

        if ($data->otp_used_datetime !== null) {
            throw new Exception('Kode OTP sudah digunakan');
        }

        if (! password_verify($OTPCode, $data->otp_value)) {
            throw new Exception('Kode OTP tidak valid');
        }

        if (Time::now()->isAfter(Time::parse($data->otp_expired_datetime))) {
            throw new Exception('Kode OTP sudah kedaluwarsa');
        }

        $now = Time::now()->toDateTimeString();

        return $this->db->table('log_otp')
            ->where('otp_id', $data->otp_id)
            ->update([
                'otp_used_datetime'    => $now,
                'otp_updated_datetime' => $now,
            ]);
    }
}
