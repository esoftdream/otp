<?php

namespace Esoftdream\OTP\Tests;

use PHPUnit\Framework\TestCase;
use Esoftdream\OTP\OTP;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\Database\BaseResult;
use CodeIgniter\Database\BaseBuilder;
use CodeIgniter\I18n\Time;
use Exception;
use RuntimeException;

class OTPTest extends TestCase
{
    private $db;
    private $builder;

    protected function setUp(): void
    {
        $this->db = $this->createMock(BaseConnection::class);
        $this->builder = $this->createMock(BaseBuilder::class);
        
        $this->db->method('table')->willReturn($this->builder);
        $this->builder->method('where')->willReturnSelf();
        $this->builder->method('orderBy')->willReturnSelf();
        $this->builder->method('limit')->willReturnSelf();
    }

    public function testGenerateSuccess()
    {
        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        // Sekarang tidak mengekspektasikan delete
        $this->builder->expects($this->never())->method('delete');
        $this->builder->expects($this->once())->method('insert')->willReturn(true);

        $result = $otp->generate();

        $this->assertArrayHasKey('otp', $result);
        $this->assertArrayHasKey('expired', $result);
        $this->assertEquals(6, strlen($result['otp']));
    }

    public function testVerifyResilientSuccess()
    {
        // Simulasi 2 record aktif, user memasukkan kode yang bukan terbaru (yang ke-2)
        $otpValue1 = '111111'; // Terbaru
        $otpValue2 = '222222'; // Sebelumnya
        
        $hashed1 = password_hash($otpValue1, PASSWORD_BCRYPT);
        $hashed2 = password_hash($otpValue2, PASSWORD_BCRYPT);
        
        $expiredAt = Time::now('UTC')->addMinutes(10)->toDateTimeString();

        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $mockRecords = [
            (object)[
                'otp_id' => 101,
                'otp_value' => $hashed1,
                'otp_expired_datetime' => $expiredAt,
                'otp_used_datetime' => null
            ],
            (object)[
                'otp_id' => 100,
                'otp_value' => $hashed2,
                'otp_expired_datetime' => $expiredAt,
                'otp_used_datetime' => null
            ]
        ];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getResult')->willReturn($mockRecords);
        $this->builder->method('get')->willReturn($resultMock);

        $this->builder->expects($this->once())
            ->method('update')
            ->with($this->equalTo(['otp_used_datetime' => Time::now('UTC')->toDateTimeString(), 'otp_updated_datetime' => Time::now('UTC')->toDateTimeString()])) // Note: ini bisa gagal karena Time::now() berbeda tipis, tapi markAsUsed pakai Time::now() yang baru
            ->willReturn(true);
            
        // Mock markAsUsed update calls
        $this->builder->method('update')->willReturn(true);

        // Verifikasi menggunakan kode yang ke-2 (resilience test)
        $this->assertTrue($otp->verify($otpValue2));
    }

    public function testVerifyExpiredFails()
    {
        $otpValue = '123456';
        $hashedValue = password_hash($otpValue, PASSWORD_BCRYPT);
        $expiredAt = Time::now('UTC')->subMinutes(1)->toDateTimeString();

        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $mockRecords = [(object)[
            'otp_id' => 10,
            'otp_value' => $hashedValue,
            'otp_expired_datetime' => $expiredAt,
            'otp_used_datetime' => null
        ]];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getResult')->willReturn($mockRecords);
        $this->builder->method('get')->willReturn($resultMock);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Kode OTP sudah kedaluwarsa');

        $otp->verify($otpValue);
    }
}
