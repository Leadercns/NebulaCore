<?php
/**
 * 文档直链访问 - 返回 JSON
 * 任何文档只要存在且 id 正确均可访问，不区分 owner_type
 */
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

$docId = isset($_GET['id']) ? intval($_GET['id']) : 0;
if ($docId <= 0) {
    http_response_code(400);
    echo json_encode(['error' => '缺少文档ID']);
    exit;
}

$host = 'localhost';
$port = 3306;
$dbname = 数据库名称;
$user = 数据库用户;
$pass = 数据库密码;

try {
    $pdo = new PDO("mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $stmt = $pdo->prepare("SELECT title, content FROM documents WHERE id = ?");
    $stmt->execute([$docId]);
    $doc = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$doc) {
        http_response_code(404);
        echo json_encode(['error' => '文档不存在']);
        exit;
    }
    
    $content = json_decode($doc['content'], true);
    if ($content === null && $doc['content'] !== null) {
        $content = $doc['content'];
    }
    
    echo json_encode([
        'title' => $doc['title'],
        'content' => $content
    ], JSON_UNESCAPED_UNICODE);
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => '数据库错误']);
}
?>