<?php
require __DIR__ . '/config_mysqli.php';
require __DIR__ . '/csrf.php';

// ตรวจสอบว่าเป็น method POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  header('Location: register.php'); exit;
}
// ตรวจสอบ CSRF token
if (!csrf_check($_POST['csrf'] ?? '')) {
  $_SESSION['flash'] = 'Invalid request. Please try again.';
  header('Location: register.php'); exit;
}

// รับและทำความสะอาดข้อมูล
$email = trim($_POST['email'] ?? '');
$pass  = $_POST['password'] ?? '';
$name  = trim($_POST['display_name'] ?? '');

// ตรวจสอบว่าอีเมลและรหัสผ่านไม่ว่างเปล่า
if ($email === '' || $pass === '') {
  $_SESSION['flash'] = 'Email and password are required.';
  header('Location: register.php'); exit;
}

// ตรวจสอบความยาวรหัสผ่าน (แนะนำให้มีอย่างน้อย 8 ตัว)
if (strlen($pass) < 8) {
  $_SESSION['flash'] = 'Password must be at least 8 characters.';
  header('Location: register.php'); exit;
}

try {
  // 1. ตรวจสอบว่าอีเมลนี้ถูกใช้ไปแล้วหรือยัง
  $stmt_check = $mysqli->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
  $stmt_check->bind_param('s', $email);
  $stmt_check->execute();
  if ($stmt_check->get_result()->num_rows > 0) {
    $_SESSION['flash'] = 'This email is already registered.';
    header('Location: register.php'); exit;
  }
  $stmt_check->close();
  
  // 2. เข้ารหัสรหัสผ่าน
  $password_hash = password_hash($pass, PASSWORD_DEFAULT);
  
  // 3. บันทึกข้อมูลผู้ใช้ใหม่ลงในฐานข้อมูล
  $stmt_insert = $mysqli->prepare('INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?)');
  $stmt_insert->bind_param('sss', $email, $name, $password_hash);
  $stmt_insert->execute();
  $new_user_id = $mysqli->insert_id; // ได้ ID ของผู้ใช้ที่เพิ่งสร้าง
  $stmt_insert->close();
  
  // 4. เข้าสู่ระบบอัตโนมัติ (หรือจะให้กลับไปหน้า login ก็ได้)
  $_SESSION['user_id'] = (int)$new_user_id;
  $_SESSION['user_name'] = $name ?: $email; // ใช้ชื่อที่ตั้ง ถ้าไม่มีก็ใช้อีเมล
  
  // อัปเดต last_login ทันที
  $stmt_update = $mysqli->prepare('UPDATE users SET last_login = NOW() WHERE id = ?');
  $stmt_update->bind_param('i', $_SESSION['user_id']);
  $stmt_update->execute();
  $stmt_update->close();

  header('Location: dashboard.php'); // ไปยังหน้าแดชบอร์ด
  exit;

} catch (mysqli_sql_exception $e) {
  // ดักจับ error ที่อาจเกิดขึ้นเช่น email ซ้ำ (แม้จะเช็คไปแล้วก็ตาม)
  // หาก error code เป็น 1062 (Duplicate entry for key 'email') 
  if ($e->getCode() === 1062) {
     $_SESSION['flash'] = 'This email is already registered.';
     header('Location: register.php'); exit;
  }
  
  // สำหรับ error อื่นๆ ที่ไม่คาดคิด
  $_SESSION['flash'] = 'Server error. Please try again.';
  // ในการใช้งานจริง ควร log $e แทนการแสดงให้ผู้ใช้เห็น
  header('Location: register.php'); exit;
} catch (Throwable $e) {
  $_SESSION['flash'] = 'Server error. Please try again.';
  header('Location: register.php'); exit;
}

?>