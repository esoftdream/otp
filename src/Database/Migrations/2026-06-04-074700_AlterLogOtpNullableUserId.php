<?php

namespace Esoftdream\OTP\Database\Migrations;

use CodeIgniter\Database\Migration;

class AlterLogOtpNullableUserId extends Migration
{
    public function up()
    {
        // 1. Ubah otp_user_id menjadi nullable
        $this->forge->modifyColumn('log_otp', [
            'otp_user_id' => [
                'name'       => 'otp_user_id',
                'type'       => 'INT',
                'constraint' => 10,
                'unsigned'   => true,
                'null'       => true,
            ],
        ]);

        // 2. Tambah kolom otp_identifier
        $this->forge->addColumn('log_otp', [
            'otp_identifier' => [
                'type'       => 'VARCHAR',
                'constraint' => 100,
                'null'       => true,
                'after'      => 'otp_user_id',
                'comment'    => 'Identifier seperti email/telepon jika user ID belum ada',
            ],
        ]);
    }

    public function down()
    {
        // 1. Hapus kolom otp_identifier
        $this->forge->dropColumn('log_otp', 'otp_identifier');

        // 2. Kembalikan otp_user_id menjadi NOT NULL
        $this->forge->modifyColumn('log_otp', [
            'otp_user_id' => [
                'name'       => 'otp_user_id',
                'type'       => 'INT',
                'constraint' => 10,
                'unsigned'   => true,
                'null'       => false,
            ],
        ]);
    }
}
