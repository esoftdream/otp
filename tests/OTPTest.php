<?php

namespace Esoftdream\OTP\Tests;

use PHPUnit\Framework\TestCase;
use Esoftdream\OTP\OTP;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\Database\BaseResult;
use CodeIgniter\Database\BaseBuilder;
use Exception;

class OTPTest extends TestCase
{
    private $db;
    private $builder;

    protected function setUp(): void
    {
        $this->db = $this->createMock(BaseConnection::class);
        $this->builder = $this->createMock(BaseBuilder::class);
        
        $this->db->method('table')->willReturn($this->builder);
    }

    public function testGenerateSuccess()
    {
        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $this->builder->method('where')->willReturnSelf();
        
        // delete() will be called once
        $this->builder->expects($this->once())
            ->method('delete');

        $this->builder->expects($this->once())
            ->method('insert')
            ->willReturn(true);

        $this->db->method('affectedRows')->willReturn(1);

        $result = $otp->generate();

        $this->assertArrayHasKey('otp', $result);
        $this->assertArrayHasKey('expired', $result);
        $this->assertEquals(6, strlen($result['otp']));
    }

    public function testVerifyFailsIfTypeNotSet()
    {
        $otp = new OTP('member', 1, $this->db);
        
        $this->expectException(Exception::class);
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
            'otp_expired_datetime' => $expiredAt
        ];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getRowObject')->willReturn($mockData);

        $this->builder->method('select')->willReturnSelf();
        $this->builder->method('where')->willReturnSelf();
        $this->builder->method('orderBy')->willReturnSelf();
        $this->builder->method('get')->willReturn($resultMock);
        $this->builder->method('set')->willReturnSelf();

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
            'otp_expired_datetime' => $expiredAt
        ];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getRowObject')->willReturn($mockData);

        $this->builder->method('select')->willReturnSelf();
        $this->builder->method('where')->willReturnSelf();
        $this->builder->method('orderBy')->willReturnSelf();
        $this->builder->method('get')->willReturn($resultMock);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Kode OTP sudah kedaluwarsa');

        $otp->verify($otpValue);
    }
}
