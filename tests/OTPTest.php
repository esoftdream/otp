<?php

namespace Esoftdream\OTP\Tests;

use PHPUnit\Framework\TestCase;
use Esoftdream\OTP\OTP;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\Database\BaseResult;
use CodeIgniter\Database\BaseBuilder;
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
        $this->builder->method('select')->willReturnSelf();
        $this->builder->method('where')->willReturnSelf();
        $this->builder->method('orderBy')->willReturnSelf();
        $this->builder->method('limit')->willReturnSelf();
    }

    public function testGenerateSuccess()
    {
        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $this->builder->expects($this->once())
            ->method('delete');

        $this->builder->expects($this->once())
            ->method('insert')
            ->willReturn(true);

        $result = $otp->generate();

        $this->assertArrayHasKey('otp', $result);
        $this->assertArrayHasKey('expired', $result);
        $this->assertEquals(6, strlen($result['otp']));
    }

    public function testVerifyFailsIfTypeNotSet()
    {
        $otp = new OTP('member', 1, $this->db);
        
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('OTP type belum diset');
        
        $otp->verify('123456');
    }

    public function testVerifySuccess()
    {
        $otpValue = '123456';
        $hashedValue = password_hash($otpValue, PASSWORD_DEFAULT);
        $expiredAt = date('Y-m-d H:i:s', strtotime('+10 minutes'));

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

        $this->builder->expects($this->once())
            ->method('update')
            ->willReturn(true);

        $this->assertTrue($otp->verify($otpValue));
    }

    public function testVerifyExpiredFails()
    {
        $otpValue = '123456';
        $hashedValue = password_hash($otpValue, PASSWORD_DEFAULT);
        $expiredAt = date('Y-m-d H:i:s', strtotime('-10 minutes'));

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
        $hashedValue = password_hash($otpValue, PASSWORD_DEFAULT);
        $expiredAt = date('Y-m-d H:i:s', strtotime('+10 minutes'));

        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        // Mock data dengan otp_used_datetime yang sudah terisi
        $mockData = (object)[
            'otp_id' => 10,
            'otp_value' => $hashedValue,
            'otp_expired_datetime' => $expiredAt,
            'otp_used_datetime' => date('Y-m-d H:i:s')
        ];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getRow')->willReturn($mockData);
        $this->builder->method('get')->willReturn($resultMock);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Kode OTP sudah digunakan');

        $otp->verify($otpValue);
    }

    public function testVerifyWrongCodeFails()
    {
        $otpValue = '123456';
        $wrongValue = '654321';
        $hashedValue = password_hash($otpValue, PASSWORD_DEFAULT);
        $expiredAt = date('Y-m-d H:i:s', strtotime('+10 minutes'));

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
        $this->expectExceptionMessage('Kode OTP tidak valid');

        $otp->verify($wrongValue);
    }

    public function testVerifyNotFoundFails()
    {
        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getRow')->willReturn(null);
        $this->builder->method('get')->willReturn($resultMock);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Kode OTP tidak ditemukan');

        $otp->verify('123456');
    }

    public function testVerifyWrongTypeFails()
    {
        // Skenario: Di DB ada OTP untuk type 'forgot', tapi kita verifikasi dengan type 'profile'
        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'profile'; 

        // Database tidak menemukan data karena filter 'otp_type' => 'profile' tidak cocok
        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getRow')->willReturn(null);

        $this->builder->method('get')->willReturn($resultMock);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Kode OTP tidak ditemukan');

        $otp->verify('123456');
    }

    public function testVerifyWithSpacesSuccess()
    {
        $otpValue = '123456';
        $hashedValue = password_hash($otpValue, PASSWORD_DEFAULT);
        $expiredAt = date('Y-m-d H:i:s', strtotime('+10 minutes'));

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

        // Test dengan spasi di awal dan akhir
        $this->assertTrue($otp->verify(' 123456 '));
    }

    public function testVerifyWithLeadingZerosSuccess()
    {
        $otpValue = '001234';
        $hashedValue = password_hash($otpValue, PASSWORD_DEFAULT);
        $expiredAt = date('Y-m-d H:i:s', strtotime('+10 minutes'));

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

        // Test dengan input '1234' untuk OTP asli '001234'
        $this->assertTrue($otp->verify('1234'));
    }
}
