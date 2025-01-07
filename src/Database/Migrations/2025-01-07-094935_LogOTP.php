<?php

namespace Esoftdream\OTP\Database\Migrations;

use CodeIgniter\Database\Migration;

class LogOTP extends Migration
{
    public function up()
    {
        // atc_ewallet
        $this->forge->addField([
            'otp_id' => [
                'type'           => 'INT',
                'constraint'     => 10,
                'unsigned'       => true,
                'auto_increment' => true,
            ],
            'otp_user_id' => [
                'type'       => 'INT',
                'constraint' => 10,
                'unsigned'   => true,
            ],
            'otp_user_type' => [
                'type'       => 'ENUM',
                'constraint' => ['member', 'admin'],
                'comment'    => 'Tipe User',
                'default'    => 'member',
            ],
            'otp_type' => [
                'type'       => 'VARCHAR',
                'constraint' => 20,
                'comment'    => 'Tipe Kegunaan OTP',
            ],
            'otp_value' => [
                'type'       => 'VARCHAR',
                'constraint' => 255,
                'comment'    => 'Kode OTP',
            ],
            'otp_expired_datetime' => [
                'type' => 'DATETIME',
            ],
            'otp_updated_datetime' => [
                'type'    => 'DATETIME',
                'null'    => true,
                'default' => null,
                'comment' => 'Tanggal-waktu OTP diperbarui',
            ],
            'otp_created_datetime' => [
                'type'    => 'DATETIME',
                'null'    => true,
                'comment' => 'Tanggal-waktu OTP dibuat',
            ],
            'otp_used_datetime' => [
                'type'    => 'DATETIME',
                'null'    => true,
                'default' => null,
                'comment' => 'Tanggal-waktu OTP digunakan',
            ],
        ]);

        $this->forge->addKey('otp_id', true);
        $this->forge->createTable('log_otp', true, [
            'comment' => 'Pencatatan log OTP untuk Admin & Member',
        ]);

    }

    public function down()
    {
        $this->forge->dropTable('log_otp', true);
    }
}
