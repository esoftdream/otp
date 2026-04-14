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

        // chaining
        $this->builder->method('select')->willReturnSelf();
        $this->builder->method('where')->willReturnSelf();
        $this->builder->method('orderBy')->willReturnSelf();
        $this->builder->method('limit')->willReturnSelf();

        // transaction (WAJIB setelah refactor)
        $this->db->method('transStart')->willReturn(null);
        $this->db->method('transComplete')->willReturn(null);
    }

    public function testGenerateSuccess()
    {
        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        // ❌ delete sudah dihapus → tidak perlu di-expect

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
        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        // Karena sekarang query pakai "otp_used_datetime IS NULL"
        // maka data used tidak akan pernah keambil → dianggap tidak ditemukan
        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getRow')->willReturn(null);

        $this->builder->method('get')->willReturn($resultMock);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Kode OTP tidak ditemukan');

        $otp->verify('123456');
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
        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'profile'; 

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getRow')->willReturn(null);

        $this->builder->method('get')->willReturn($resultMock);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Kode OTP tidak ditemukan');

        $otp->verify('123456');
    }
}
