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
        $this->db->method('affectedRows')->willReturn(1);
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
        $expiredAt = Time::now('Asia/Jakarta')->addMinutes(10)->toDateTimeString();

        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $mockRecords = [
            (object)['otp_id' => 101, 'otp_value' => $hashed1, 'otp_expired_datetime' => $expiredAt, 'otp_used_datetime' => null],
            (object)['otp_id' => 100, 'otp_value' => $hashed2, 'otp_expired_datetime' => $expiredAt, 'otp_used_datetime' => null]
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
        $expiredAt = Time::now('Asia/Jakarta')->addMinutes(10)->toDateTimeString();

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
        // Skenario: Ada 2 record dengan kode yang sama (mungkin generate ulang kode yang sama secara kebetulan)
        // Yang satu sudah expired, yang satu masih valid.
        $otpValue = '123456';
        $hashed = password_hash($otpValue, PASSWORD_BCRYPT);
        
        $expiredTime = Time::now('Asia/Jakarta')->subMinutes(5)->toDateTimeString();
        $validTime = Time::now('Asia/Jakarta')->addMinutes(10)->toDateTimeString();

        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $mockRecords = [
            (object)['otp_id' => 101, 'otp_value' => $hashed, 'otp_expired_datetime' => $validTime, 'otp_used_datetime' => null],
            (object)['otp_id' => 100, 'otp_value' => $hashed, 'otp_expired_datetime' => $expiredTime, 'otp_used_datetime' => null]
        ];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getResult')->willReturn($mockRecords);
        $this->builder->method('get')->willReturn($resultMock);
        $this->builder->method('update')->willReturn(true);

        // Harus berhasil karena menemukan yang ID 101 yang masih valid
        $this->assertTrue($otp->verify($otpValue));
    }

    public function testVerifyWrongCodeAllFails()
    {
        $otpValue1 = '111111';
        $otpValue2 = '222222';
        $hashed1 = password_hash($otpValue1, PASSWORD_BCRYPT);
        $hashed2 = password_hash($otpValue2, PASSWORD_BCRYPT);

        $otp = new OTP('member', 1, $this->db);
        $otp->type = 'forgot';

        $mockRecords = [
            (object)['otp_id' => 101, 'otp_value' => $hashed1, 'otp_expired_datetime' => 'any', 'otp_used_datetime' => null],
            (object)['otp_id' => 100, 'otp_value' => $hashed2, 'otp_expired_datetime' => 'any', 'otp_used_datetime' => null]
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
        $expiredAt = Time::now('Asia/Jakarta')->subMinutes(1)->toDateTimeString();

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

    public function testConstructorThrowsExceptionWhenBothNull()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('User ID atau Identifier harus diisi salah satu.');

        new OTP('member', null, $this->db, null);
    }

    public function testGenerateWithIdentifierSuccess()
    {
        // Inisialisasi dengan identifier dan userId = null
        $otp = new OTP('member', null, $this->db, 'john@example.com');
        $otp->type = 'forgot';

        $this->builder->expects($this->once())
            ->method('insert')
            ->with($this->callback(function ($data) {
                return $data['otp_user_id'] === null && $data['otp_identifier'] === 'john@example.com';
            }))
            ->willReturn(true);

        $result = $otp->generate();

        $this->assertArrayHasKey('otp', $result);
        $this->assertArrayHasKey('expired', $result);
        $this->assertEquals(6, strlen($result['otp']));
    }

    public function testVerifyWithIdentifierSuccess()
    {
        $otpValue = '123456';
        $hashedValue = password_hash($otpValue, PASSWORD_BCRYPT);
        $expiredAt = Time::now('Asia/Jakarta')->addMinutes(10)->toDateTimeString();

        // Inisialisasi dengan identifier dan userId = null
        $otp = new OTP('member', null, $this->db, 'john@example.com');
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

        // Verifikasi bahwa query where menggunakan otp_identifier, bukan otp_user_id
        $whereCalls = [];
        $this->builder->method('where')->willReturnCallback(function ($key, $value = null) use (&$whereCalls) {
            $whereCalls[] = $key;
            return $this->builder;
        });

        $this->assertTrue($otp->verify($otpValue));

        $this->assertCount(3, $whereCalls);
        $firstWhere = $whereCalls[0];
        $this->assertIsArray($firstWhere);
        $this->assertArrayNotHasKey('otp_user_id', $firstWhere);
        $this->assertEquals('john@example.com', $firstWhere['otp_identifier']);
        $this->assertEquals('otp_id', $whereCalls[1]);
        $this->assertEquals('otp_used_datetime', $whereCalls[2]);
    }

    public function testVerifyReturnsFalseOnConcurrentDoubleHit()
    {
        $otpValue = '123456';
        $hashedValue = password_hash($otpValue, PASSWORD_BCRYPT);
        $expiredAt = Time::now('Asia/Jakarta')->addMinutes(10)->toDateTimeString();

        $db = $this->createMock(BaseConnection::class);
        $builder = $this->createMock(BaseBuilder::class);

        $db->method('table')->willReturn($builder);
        // Simulate concurrent request winning the race: 0 affected rows
        $db->method('affectedRows')->willReturn(0);
        $builder->method('where')->willReturnSelf();
        $builder->method('orderBy')->willReturnSelf();
        $builder->method('limit')->willReturnSelf();
        $builder->method('update')->willReturn(true);

        $otp = new OTP('member', 1, $db);
        $otp->type = 'forgot';

        $mockRecords = [(object)[
            'otp_id' => 10,
            'otp_value' => $hashedValue,
            'otp_expired_datetime' => $expiredAt,
            'otp_used_datetime' => null
        ]];

        $resultMock = $this->createMock(BaseResult::class);
        $resultMock->method('getResult')->willReturn($mockRecords);
        $builder->method('get')->willReturn($resultMock);

        // When affectedRows is 0, verify() returns false (atomic double-hit prevention)
        $this->assertFalse($otp->verify($otpValue));
    }
}
