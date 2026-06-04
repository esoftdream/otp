# Esoftdream OTP Module

Modul untuk menangani pembuatan dan verifikasi One-Time Password (OTP) secara aman dan tangguh untuk proyek PHP (CodeIgniter 4).

## Fitur Utama

- **Resiliensi Tinggi**: Mendukung verifikasi terhadap beberapa kode OTP aktif secara bersamaan (mencegah masalah klik ganda atau delay pengiriman).
- **Normalisasi Input Otomatis**: Secara cerdas membersihkan spasi, simbol, dan menangani *leading zeros* (angka nol di depan).
- **Keamanan**: Penyimpanan kode menggunakan hashing Bcrypt.
- **Standar Waktu UTC**: Menggunakan standar UTC untuk mencegah masalah perbedaan zona waktu server.

## Persyaratan

- PHP 8.1 atau lebih baru
- Proyek berbasis CodeIgniter 4

## Instalasi Database

Jalankan migration untuk membuat tabel `log_otp`:

```bash
php spark migrate:latest -n Esoftdream\OTP
```

## Cara Penggunaan

### 1. Inisialisasi

Ada dua cara untuk menginisialisasi modul ini, tergantung apakah User ID sudah tersedia atau belum:

#### A. Menggunakan User ID (Kasus Umum)
Gunakan cara ini jika user sudah terdaftar di database (misalnya untuk Forgot Password, Verifikasi Transaksi, dll):
```php
use Esoftdream\OTP\OTP;

// Parameter: userType, userId
$otp = new OTP('member', 123);
$otp->type = 'forgot_password'; // Wajib set tipe kegunaan OTP
```

#### B. Menggunakan Identifier (Kasus Registrasi / User belum ada)
Jika User ID belum dibuat di database (misalnya verifikasi email/telepon saat registrasi), Anda bisa menggunakan *identifier* unik seperti email atau nomor telepon sebagai gantinya:
```php
use Esoftdream\OTP\OTP;

// Parameter: userType, userId (null), db connection (null), identifier
$otp = new OTP('member', null, null, 'john.doe@example.com');
$otp->type = 'registration';
```

#### Pengaturan Opsional
Anda juga bisa mengatur panjang kode OTP (default 6 digit) dan masa berlaku (default 10 menit):
```php
$otp->setLength(6)->setExpiry(5);
```

### 2. Membuat OTP (Generate)

```php
$result = $otp->generate();

/**
 * $result berisi:
 * [
 *    'otp' => '102678',
 *    'expired' => '2026-04-14 14:30:00'
 * ]
 */
```

### 3. Verifikasi OTP

Sistem ini sangat fleksibel. Pengguna dapat menginput kode dengan spasi atau simbol, dan jika ada pengiriman ulang, kode sebelumnya (jika belum expired) akan tetap bisa divalidasi.

```php
try {
    // Input bisa berupa ' 10-26 78 ', akan tetap diproses sebagai '102678'
    if ($otp->verify($userInput)) {
        echo "OTP Berhasil divalidasi!";
    }
} catch (\Exception $e) {
    // Menangani error: 'Kode OTP tidak ditemukan', 'Kode OTP tidak valid', atau 'Kode OTP sudah kedaluwarsa'
    echo "Gagal: " . $e->getMessage();
}
```

## Kontribusi

Silakan ajukan PR untuk peningkatan fitur atau perbaikan bug. Pastikan untuk selalu menjalankan unit test sebelum melakukan commit.

```bash
./vendor/bin/phpunit tests/OTPTest.php
```