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

    public function __construct(string $userType, int $userID)
    {
        $this->db = Database::connect();

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
        $OTPCode    = random_string('numeric', 6);
        $OTPExpired = Time::now()->addMinutes(10)->toDateTimeString();

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
        // OTP builder
        $OPTBuilder = $this->db->table('log_otp');

        // cek dulu apakah ada data sebelumnya
        $OPTBuilder->where('otp_type', $this->type);
        $OPTBuilder->where('otp_user_type', $this->userType);
        $OPTBuilder->where('otp_user_id', $this->userID);
        $OPTBuilder->where('otp_used_datetime IS NULL');
        $OPTBuilder->where('DATE(otp_created_datetime) = DATE(NOW())');

        $datOTP = $OPTBuilder->get()->getRow();

        if (! empty($datOTP)) {
            // hapus data OTP lama
            $OPTBuilder->where('otp_id', $datOTP->otp_id);
            $OPTBuilder->delete();
        }

        $now = Time::now();

        $OPTBuilder->insert([
            'otp_user_id'          => $this->userID,
            'otp_user_type'        => $this->userType,
            'otp_type'             => $this->type,
            'otp_value'            => password_hash($OTPCode, PASSWORD_DEFAULT),
            'otp_expired_datetime' => $OTPExpired,
            'otp_updated_datetime' => $now->toDateTimeString(),
            'otp_created_datetime' => $now->toDateTimeString(),
        ]);

        return (bool) ($this->db->affectedRows() > 0);
    }

    /**
     * Proses verifikasi OTP
     */
    public function verify(string $OTPCode): bool
    {
        $now = Time::now();

        $data = $this->db->table('log_otp')
            ->select('otp_id, otp_expired_datetime, otp_used_datetime, otp_value')
            ->where('otp_user_id', $this->userID)
            ->where('otp_user_type', $this->userType)
            ->where('otp_type', $this->type)
            ->where('otp_used_datetime IS NULL')
            ->where('DATE(otp_created_datetime) = DATE(NOW())')
            ->get()
            ->getRowObject();

        if (empty($data)) {
            throw new Exception('Kode OTP salah / kode telah digunakan');
        }

        if ($data->otp_expired_datetime < $now->toDateTimeString()) {
            throw new Exception('Kode OTP sudah kedaluwarsa');
        }

        if (! password_verify($OTPCode, $data->otp_value)) {
            throw new Exception('Kode OTP salah');
        }

        // model OTP
        $this->db->table('log_otp')
            ->set('otp_used_datetime', $now->toDateTimeString())
            ->set('otp_updated_datetime', $now->toDateTimeString())
            ->where('otp_id', $data->otp_id)
            ->update();

        return (bool) ($this->db->affectedRows() > 0);
    }
}
