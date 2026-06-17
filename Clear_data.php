<?php
/**
 * 一键重置数据库脚本
 * 功能：清空所有表数据、重置自增ID、创建超级管理员 a1 / 123456
 * 使用方法：浏览器访问此文件，执行后应立即删除
 */

// 数据库配置
$host = 'localhost';
$port = 3306;
$dbname = 数据库名称;
$user = 数据库用户;
$pass = 数据库密码;

try {
    // 连接数据库
    $pdo = new PDO("mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // 开始事务
    $pdo->beginTransaction();
    
    // 1. 关闭外键检查
    $pdo->exec("SET FOREIGN_KEY_CHECKS = 0");
    
    // 2. 清空所有表数据
    $pdo->exec("DELETE FROM `documents`");
    $pdo->exec("DELETE FROM `cards`");
    $pdo->exec("DELETE FROM `api_users`");
    $pdo->exec("DELETE FROM `apis`");
    $pdo->exec("DELETE FROM `developers`");
    
    // 3. 重置所有表自增 ID
    $pdo->exec("ALTER TABLE `documents` AUTO_INCREMENT = 1");
    $pdo->exec("ALTER TABLE `cards` AUTO_INCREMENT = 1");
    $pdo->exec("ALTER TABLE `api_users` AUTO_INCREMENT = 1");
    $pdo->exec("ALTER TABLE `apis` AUTO_INCREMENT = 1");
    $pdo->exec("ALTER TABLE `developers` AUTO_INCREMENT = 1");
    
    // 4. 创建超级管理员 a1，密码 123456
    $username = 'a1';
    $passwordPlain = '123456';
    $passwordHash = password_hash($passwordPlain, PASSWORD_DEFAULT);
    $userkey = bin2hex(random_bytes(32)); // 生成一个随机的 userkey
    $email = 'admin@example.com';
    $is_admin = 1;
    $integral = 0;
    
    $stmt = $pdo->prepare("INSERT INTO `developers` (`username`, `userkey`, `password`, `email_address`, `is_admin`, `integral`) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->execute([$username, $userkey, $passwordHash, $email, $is_admin, $integral]);
    
    // 5. 开启外键检查
    $pdo->exec("SET FOREIGN_KEY_CHECKS = 1");
    
    // 提交事务
    $pdo->commit();
    
    echo "✅ 数据库重置成功！<br>";
    echo "所有表数据已清空，自增 ID 已重置。<br>";
    echo "超级管理员账号创建成功：<br>";
    echo "用户名：<strong>a1</strong><br>";
    echo "密码：<strong>123456</strong><br>";
    echo "userkey：<strong>{$userkey}</strong><br>";
    echo "请妥善保管此信息。<br>";
    echo "<hr>";
    echo "⚠️ 请立即删除本脚本文件，以免被恶意利用。";
    
} catch (PDOException $e) {
    // 回滚事务
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    // 确保外键检查重新开启
    try {
        $pdo->exec("SET FOREIGN_KEY_CHECKS = 1");
    } catch (Exception $ex) {}
    
    echo "❌ 数据库重置失败：<br>";
    echo "错误信息：" . $e->getMessage();
}
?>