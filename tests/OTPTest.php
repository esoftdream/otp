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
        $this->builder->method('select')->willReturnSelf(); // compatibility
    }

    public function testGenerateSuccess()
    {
        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $this->builder->expects($this->once())->method('delete');
        $this->builder->expects($this->once())->method('insert')->willReturn(true);

        $result = $otp->generate();

        $this->assertArrayHasKey('otp', $result);
        $this->assertArrayHasKey('expired', $result);
        $this->assertEquals(6, strlen($result['otp']));
    }

    public function testVerifySuccess()
    {
        $otpValue = '123456';
        $hashedValue = password_hash($otpValue, PASSWORD_BCRYPT);
        $expiredAt = Time::now('UTC')->addMinutes(10)->toDateTimeString();

        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $mockData = (object)[
            'otp_id' => 10,
            'otp_value' => $hashedValue,
            'otp_expired_datetime' => $expiredAt,
            'otp_used_datetime' => null
        ];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getRow')->willReturn($mockData);
        $this->builder->method('get')->willReturn($resultMock);

        $this->builder->expects($this->once())->method('update')->willReturn(true);

        $this->assertTrue($otp->verify($otpValue));
    }

    public function testVerifyWithNormalizationSuccess()
    {
        $otpValue = '001234';
        $hashedValue = password_hash($otpValue, PASSWORD_BCRYPT);
        $expiredAt = Time::now('UTC')->addMinutes(10)->toDateTimeString();

        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $mockData = (object)[
            'otp_id' => 10,
            'otp_value' => $hashedValue,
            'otp_expired_datetime' => $expiredAt,
            'otp_used_datetime' => null
        ];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getRow')->willReturn($mockData);
        $this->builder->method('get')->willReturn($resultMock);
        $this->builder->method('update')->willReturn(true);

        // Test normalization: spasi, karakter non-digit (diabaikan regex), dan leading zeros
        $this->assertTrue($otp->verify(' 12-34 ')); 
    }

    public function testVerifyExpiredFails()
    {
        $otpValue = '123456';
        $hashedValue = password_hash($otpValue, PASSWORD_BCRYPT);
        $expiredAt = Time::now('UTC')->subMinutes(1)->toDateTimeString();

        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $mockData = (object)[
            'otp_id' => 10,
            'otp_value' => $hashedValue,
            'otp_expired_datetime' => $expiredAt,
            'otp_used_datetime' => null
        ];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getRow')->willReturn($mockData);
        $this->builder->method('get')->willReturn($resultMock);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Kode OTP sudah kedaluwarsa');

        $otp->verify($otpValue);
    }

    public function testVerifyAlreadyUsedFails()
    {
        $otpValue = '123456';
        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $mockData = (object)[
            'otp_id' => 10,
            'otp_value' => 'any_hash',
            'otp_expired_datetime' => 'any_time',
            'otp_used_datetime' => '2025-01-01 10:00:00'
        ];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getRow')->willReturn($mockData);
        $this->builder->method('get')->willReturn($resultMock);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Kode OTP sudah digunakan');

        $otp->verify($otpValue);
    }
}
