<?php

namespace Esoftdream\OTP;

use CodeIgniter\Database\BaseConnection;
use CodeIgniter\I18n\Time;
use Config\Database;
use Exception;

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

    private BaseConnection $db;

    public function __construct(string $userType, int $userID, ?BaseConnection $db = null)
    {
        $this->db = $db ?? Database::connect();

        $this->userType = $userType;
        $this->userID   = $userID;
    }

    /**
     * Generate kode OTP
     *
     * @return array Berisi kode otp & waktu kadaluarsa
     */
    public function generate(): array
    {
        if (empty($this->type)) {
            throw new Exception('OTP type belum diset');
        }

        $OTPCode = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $expired = Time::now()->addMinutes(10);

        $this->save($OTPCode, $expired);

        return [
            'otp'     => $OTPCode,
            'expired' => $expired->toDateTimeString(),
        ];
    }

    /**
     * Insert kode OTP ke database
     * Kode OTP lama yang belum digunakan akan dihapus
     */
    private function save(string $OTPCode, Time $expired): void
    {
        $now = Time::now();

        // hapus OTP lama yang belum dipakai
        $this->db->table('log_otp')
            ->where('otp_type', $this->type)
            ->where('otp_user_type', $this->userType)
            ->where('otp_user_id', $this->userID)
            ->where('otp_used_datetime IS NULL')
            ->delete();

        $this->db->table('log_otp')->insert([
            'otp_user_id'          => $this->userID,
            'otp_user_type'        => $this->userType,
            'otp_type'             => $this->type,
            'otp_value'            => password_hash($OTPCode, PASSWORD_DEFAULT),
            'otp_expired_datetime' => $expired->toDateTimeString(),
            'otp_created_datetime' => $now->toDateTimeString(),
            'otp_updated_datetime' => $now->toDateTimeString(),
        ]);

        if ($this->db->affectedRows() === 0) {
            throw new Exception('Gagal menyimpan OTP');
        }
    }

    /**
     * Proses verifikasi OTP
     */
    public function verify(string $OTPCode): bool
    {
        if (empty($this->type)) {
            throw new Exception('OTP type belum diset');
        }

        $now = Time::now();

        $data = $this->db->table('log_otp')
            ->select('otp_id, otp_value, otp_expired_datetime')
            ->where('otp_user_id', $this->userID)
            ->where('otp_user_type', $this->userType)
            ->where('otp_type', $this->type)
            ->where('otp_used_datetime IS NULL')
            ->where('otp_created_datetime >=', date('Y-m-d 00:00:00'))
            ->where('otp_created_datetime <=', date('Y-m-d 23:59:59'))
            ->orderBy('otp_id', 'DESC')
            ->get()
            ->getRowObject();

        if (! $data) {
            throw new Exception('Kode OTP salah atau sudah digunakan');
        }

        if (! password_verify($OTPCode, $data->otp_value)) {
            throw new Exception('Kode OTP tidak valid');
        }

        $expired = Time::parse($data->otp_expired_datetime);

        if ($expired->isBefore($now)) {
            throw new Exception('Kode OTP sudah kedaluwarsa');
        }

        // tandai OTP sudah digunakan
        $this->db->table('log_otp')
            ->set('otp_used_datetime', $now->toDateTimeString())
            ->set('otp_updated_datetime', $now->toDateTimeString())
            ->where('otp_id', $data->otp_id)
            ->update();

        return true;
    }
}



