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

        $this->builder->expects($this->once())->method('insert')->willReturn(true);

        $result = $otp->generate();

        $this->assertArrayHasKey('otp', $result);
        $this->assertArrayHasKey('expired', $result);
        $this->assertEquals(6, strlen($result['otp']));
    }

    public function testVerifyResilientSuccess()
    {
        // Skenario: 2 OTP aktif, user masukkan yang kedua (lama)
        $otpValue1 = '111111'; 
        $otpValue2 = '222222'; 
        
        $hashed1 = password_hash($otpValue1, PASSWORD_BCRYPT);
        $hashed2 = password_hash($otpValue2, PASSWORD_BCRYPT);

        $now = Time::now('UTC');
        $expiredAt = $now->addMinutes(10)->toDateTimeString();

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
        $this->builder->method('update')->willReturn(true);

        // Verifikasi kode kedua (resilience test)
        $this->assertTrue($otp->verify($otpValue2));
    }

    public function testVerifyWithNormalizationSuccess()
    {
        $otpValue = '001234';
        $hashedValue = password_hash($otpValue, PASSWORD_BCRYPT);

        $now = Time::now('UTC');
        $expiredAt = $now->addMinutes(10)->toDateTimeString();

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
        $this->builder->method('update')->willReturn(true);

        // Test normalisasi: simbol, spasi, dan leading zeros (input '1234' -> '001234')
        $this->assertTrue($otp->verify(' 12-34 ')); 
    }

    public function testVerifyOneExpiredOneValidSuccess()
    {
        // Skenario: Ada 2 record dengan kode yang sama
        $otpValue = '123456';
        $hashed = password_hash($otpValue, PASSWORD_BCRYPT);
        
        $now = Time::now('UTC');

        $expiredTime = $now->subMinutes(5)->toDateTimeString();
        $validTime   = $now->addMinutes(10)->toDateTimeString();

        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $mockRecords = [
            (object)[
                'otp_id' => 101,
                'otp_value' => $hashed,
                'otp_expired_datetime' => $validTime,
                'otp_used_datetime' => null
            ],
            (object)[
                'otp_id' => 100,
                'otp_value' => $hashed,
                'otp_expired_datetime' => $expiredTime,
                'otp_used_datetime' => null
            ]
        ];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getResult')->willReturn($mockRecords);
        $this->builder->method('get')->willReturn($resultMock);
        $this->builder->method('update')->willReturn(true);

        // Harus berhasil karena menemukan yang masih valid
        $this->assertTrue($otp->verify($otpValue));
    }

    public function testVerifyWrongCodeAllFails()
    {
        $otpValue1 = '111111';
        $otpValue2 = '222222';

        $hashed1 = password_hash($otpValue1, PASSWORD_BCRYPT);
        $hashed2 = password_hash($otpValue2, PASSWORD_BCRYPT);

        $now = Time::now('UTC');
        $validTime = $now->addMinutes(10)->toDateTimeString();

        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $mockRecords = [
            (object)[
                'otp_id' => 101,
                'otp_value' => $hashed1,
                'otp_expired_datetime' => $validTime,
                'otp_used_datetime' => null
            ],
            (object)[
                'otp_id' => 100,
                'otp_value' => $hashed2,
                'otp_expired_datetime' => $validTime,
                'otp_used_datetime' => null
            ]
        ];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getResult')->willReturn($mockRecords);
        $this->builder->method('get')->willReturn($resultMock);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Kode OTP tidak valid');

        $otp->verify('333333');
    }

    public function testVerifyNotFoundFails()
    {
        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getResult')->willReturn([]);
        $this->builder->method('get')->willReturn($resultMock);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Kode OTP tidak ditemukan atau sudah digunakan');

        $otp->verify('123456');
    }

    public function testVerifyExpiredFails()
    {
        $otpValue = '123456';
        $hashedValue = password_hash($otpValue, PASSWORD_BCRYPT);

        $now = Time::now('UTC');
        $expiredAt = $now->subMinutes(1)->toDateTimeString();

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
