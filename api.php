<?php
/**
 * 多租户 API 管理平台 - 最终安全版
 * - 开发者：使用 userkey 认证，API 操作使用 api_key 标识
 * - API 用户：使用 user_key 认证，个人信息不返回 api_key
 * - 超级管理员：管理开发者及开发者卡密
 */

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(200);
    echo json_encode(['status' => 'error', 'message' => '只支持 POST 请求'], JSON_UNESCAPED_UNICODE);
    exit;
}

// ---------- 配置 ----------
define('DB_HOST', 'localhost');
define('DB_PORT', 3306);
define('DB_NAME', 数据库名称);
define('DB_USER', 数据库用户);
define('DB_PASS', 数据库密码);
date_default_timezone_set('Asia/Shanghai');
define('SITE_URL', 实际域名); 

function getDB() {
    static $mysqli = null;
    if ($mysqli === null) {
        $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
        if ($mysqli->connect_error) {
            send_error('数据库连接失败: ' . $mysqli->connect_error);
        }
        $mysqli->set_charset('utf8mb4');
        $mysqli->query("SET NAMES utf8mb4");
    }
    return $mysqli;
}

function send_error($msg) {
    http_response_code(200);
    echo json_encode(['status' => 'error', 'message' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

function send_success($message = null, $data = null) {
    http_response_code(200);
    $resp = ['status' => 'success'];
    if ($message !== null) $resp['message'] = $message;
    if ($data !== null) $resp['data'] = $data;
    echo json_encode($resp, JSON_UNESCAPED_UNICODE);
    exit;
}

function getParams() {
    if (!empty($_POST)) return $_POST;
    $raw = file_get_contents('php://input');
    if (empty($raw)) return [];
    $json = json_decode($raw, true);
    return is_array($json) ? $json : [];
}

function generateRandomKey($length = 32) {
    return bin2hex(random_bytes($length / 2));
}

function getDeveloperByUserkey($userkey) {
    $db = getDB();
    $stmt = $db->prepare("SELECT id, username, userkey, email_address, vip_time, ban_time, integral, is_admin FROM developers WHERE userkey = ?");
    $stmt->bind_param('s', $userkey);
    $stmt->execute();
    return $stmt->get_result()->fetch_assoc();
}

function getApiByKey($apiKey) {
    $db = getDB();
    $stmt = $db->prepare("SELECT a.*, d.ban_time as developer_ban_time FROM apis a JOIN developers d ON a.developer_id = d.id WHERE a.api_key = ?");
    $stmt->bind_param('s', $apiKey);
    $stmt->execute();
    return $stmt->get_result()->fetch_assoc();
}

function getApiUserByUserKey($userKey) {
    $db = getDB();
    // 不返回 api_key，只返回用户自身信息
    $stmt = $db->prepare("SELECT u.id, u.username, u.user_key, u.email, u.integral, u.vip_time, u.ban_time, u.created_at, u.api_id FROM api_users u WHERE u.user_key = ?");
    $stmt->bind_param('s', $userKey);
    $stmt->execute();
    return $stmt->get_result()->fetch_assoc();
}

function isBanned($banTime) {
    if (!$banTime) return false;
    $ts = strtotime($banTime);
    return $ts && $ts <= time();
}

// ----------------------------- 开发者端 API -----------------------------
function dev_register($params) {
    $username = trim($params['username'] ?? '');
    $password = $params['password'] ?? '';
    $email = trim($params['email_address'] ?? '');
    if (empty($username) || empty($password) || empty($email)) send_error('用户名/密码/邮箱不能为空');
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) send_error('邮箱无效');

    $db = getDB();
    $check = $db->prepare("SELECT id FROM developers WHERE username = ? OR email_address = ?");
    $check->bind_param('ss', $username, $email);
    $check->execute();
    if ($check->get_result()->num_rows > 0) send_error('用户名或邮箱已存在');

    $userkey = generateRandomKey(64);
    $hashed = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $db->prepare("INSERT INTO developers (username, userkey, password, email_address, integral) VALUES (?, ?, ?, ?, 100)");
    $stmt->bind_param('ssss', $username, $userkey, $hashed, $email);
    if ($stmt->execute()) {
        send_success('注册成功');
    } else {
        send_error('注册失败');
    }
}

function dev_login($params) {
    $username = trim($params['username'] ?? '');
    $password = $params['password'] ?? '';
    if (empty($username) || empty($password)) send_error('用户名和密码不能为空');
    $db = getDB();
    $stmt = $db->prepare("SELECT id, username, userkey, password, email_address, vip_time, ban_time, integral FROM developers WHERE username = ?");
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    if (!$user || !password_verify($password, $user['password'])) send_error('用户名或密码错误');
    if (isBanned($user['ban_time'])) send_error('账号已被封禁至 ' . $user['ban_time']);
    send_success('登录成功', ['userkey' => $user['userkey']]);
}

function dev_reset_userkey($params, $currentDev) {
    $newKey = generateRandomKey(64);
    $db = getDB();
    $stmt = $db->prepare("UPDATE developers SET userkey = ? WHERE id = ?");
    $stmt->bind_param('si', $newKey, $currentDev['id']);
    $stmt->execute();
    send_success('重置成功', ['new_userkey' => $newKey]);
}

function dev_change_password($params, $currentDev) {
    $oldPass = $params['old_password'] ?? '';
    $newPass = $params['new_password'] ?? '';
    if (empty($oldPass) || empty($newPass)) send_error('原密码和新密码不能为空');
    $db = getDB();
    $stmt = $db->prepare("SELECT password FROM developers WHERE id = ?");
    $stmt->bind_param('i', $currentDev['id']);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    if (!password_verify($oldPass, $row['password'])) send_error('原密码错误');
    $newHash = password_hash($newPass, PASSWORD_DEFAULT);
    $upd = $db->prepare("UPDATE developers SET password = ? WHERE id = ?");
    $upd->bind_param('si', $newHash, $currentDev['id']);
    $upd->execute();
    send_success('密码修改成功');
}

function dev_redeem_card($params, $currentDev) {
    $code = trim($params['card_code'] ?? '');
    if (empty($code)) send_error('卡密不能为空');
    $db = getDB();
    $stmt = $db->prepare("SELECT * FROM cards WHERE card_code = ? AND used_by_id IS NULL AND (expire_time IS NULL OR expire_time > NOW()) AND card_type IN ('developer_integral','developer_vip')");
    $stmt->bind_param('s', $code);
    $stmt->execute();
    $card = $stmt->get_result()->fetch_assoc();
    if (!$card) send_error('无效或已使用的卡密');

    $db->begin_transaction();
    try {
        if ($card['card_type'] == 'developer_integral') {
            $points = intval($card['points']);
            $upd = $db->prepare("UPDATE developers SET integral = integral + ? WHERE id = ?");
            $upd->bind_param('ii', $points, $currentDev['id']);
            $upd->execute();
        } else {
            $days = intval($card['vip_days']);
            $newVipTime = date('Y-m-d H:i:s', strtotime("+$days days"));
            $upd = $db->prepare("UPDATE developers SET vip_time = ? WHERE id = ?");
            $upd->bind_param('si', $newVipTime, $currentDev['id']);
            $upd->execute();
        }
        $used = $db->prepare("UPDATE cards SET used_by_id = ?, used_at = NOW() WHERE id = ?");
        $used->bind_param('ii', $currentDev['id'], $card['id']);
        $used->execute();
        $db->commit();
        send_success('兑换成功');
    } catch (Exception $e) {
        $db->rollback();
        send_error('兑换失败');
    }
}

function dev_profile($params, $currentDev) {
    send_success(null, $currentDev);
}

function dev_create_api($params, $currentDev) {
    $name = trim($params['api_name'] ?? '');
    if (empty($name)) send_error('API 名称不能为空');
    $apiKey = generateRandomKey(32);
    $apiSecret = generateRandomKey(32);
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO apis (developer_id, api_name, api_key, api_secret) VALUES (?, ?, ?, ?)");
    $stmt->bind_param('isss', $currentDev['id'], $name, $apiKey, $apiSecret);
    if ($stmt->execute()) {
        send_success('创建成功', ['api_id' => $stmt->insert_id, 'api_key' => $apiKey]);
    } else {
        send_error('创建失败: ' . $db->error);
    }
}

function dev_reset_apikey($params, $currentDev) {
    $apiKey = trim($params['api_key'] ?? '');
    if (empty($apiKey)) send_error('缺少 api_key');
    $db = getDB();
    $check = $db->prepare("SELECT id FROM apis WHERE api_key = ? AND developer_id = ?");
    $check->bind_param('si', $apiKey, $currentDev['id']);
    $check->execute();
    if ($check->get_result()->num_rows == 0) send_error('API 不存在或不属于你');
    $newKey = generateRandomKey(32);
    $upd = $db->prepare("UPDATE apis SET api_key = ? WHERE api_key = ? AND developer_id = ?");
    $upd->bind_param('ssi', $newKey, $apiKey, $currentDev['id']);
    $upd->execute();
    send_success('重置成功', ['new_api_key' => $newKey]);
}

function dev_list_apis($params, $currentDev) {
    $db = getDB();
    // 只返回 api_key，不返回 api_secret
    $stmt = $db->prepare("SELECT id, api_name, api_key, created_at FROM apis WHERE developer_id = ?");
    $stmt->bind_param('i', $currentDev['id']);
    $stmt->execute();
    $apis = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    send_success(null, $apis);
}

function dev_list_api_users($params, $currentDev) {
    $apiKey = trim($params['api_key'] ?? '');
    if (empty($apiKey)) send_error('缺少 api_key');
    $db = getDB();
    $check = $db->prepare("SELECT a.id FROM apis a WHERE a.api_key = ? AND a.developer_id = ?");
    $check->bind_param('si', $apiKey, $currentDev['id']);
    $check->execute();
    $api = $check->get_result()->fetch_assoc();
    if (!$api) send_error('API 不存在或不属于你');
    $stmt = $db->prepare("SELECT id, username, email, integral, vip_time, ban_time, created_at FROM api_users WHERE api_id = ?");
    $stmt->bind_param('i', $api['id']);
    $stmt->execute();
    $users = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    send_success(null, $users);
}

function dev_modify_user_integral($params, $currentDev) {
    $apiKey = trim($params['api_key'] ?? '');
    $userId = intval($params['user_id'] ?? 0);
    $delta = intval($params['points'] ?? 0);
    if (empty($apiKey) || !$userId || $delta == 0) send_error('参数不完整');
    $db = getDB();
    $check = $db->prepare("SELECT u.id FROM api_users u JOIN apis a ON u.api_id = a.id WHERE a.api_key = ? AND a.developer_id = ? AND u.id = ?");
    $check->bind_param('sii', $apiKey, $currentDev['id'], $userId);
    $check->execute();
    if ($check->get_result()->num_rows == 0) send_error('用户不存在或不属于你的API');
    $upd = $db->prepare("UPDATE api_users SET integral = integral + ? WHERE id = ?");
    $upd->bind_param('ii', $delta, $userId);
    $upd->execute();
    send_success('积分修改成功');
}

function dev_set_user_time($params, $currentDev) {
    $apiKey = trim($params['api_key'] ?? '');
    $userId = intval($params['user_id'] ?? 0);
    $banTime = $params['ban_time'] ?? null;
    $vipTime = $params['vip_time'] ?? null;
    if (empty($apiKey) || !$userId) send_error('缺少 api_key 或 user_id');
    $db = getDB();
    $check = $db->prepare("SELECT u.id FROM api_users u JOIN apis a ON u.api_id = a.id WHERE a.api_key = ? AND a.developer_id = ? AND u.id = ?");
    $check->bind_param('sii', $apiKey, $currentDev['id'], $userId);
    $check->execute();
    if ($check->get_result()->num_rows == 0) send_error('用户不存在或不属于你的API');

    $updates = [];
    $types = '';
    $values = [];
    if ($banTime !== null) {
        $updates[] = "ban_time = ?";
        $types .= 's';
        $values[] = ($banTime === '' ? null : $banTime);
    }
    if ($vipTime !== null) {
        $updates[] = "vip_time = ?";
        $types .= 's';
        $values[] = ($vipTime === '' ? null : $vipTime);
    }
    if (empty($updates)) send_error('没有需要更新的字段');
    $sql = "UPDATE api_users SET " . implode(',', $updates) . " WHERE id = ?";
    $types .= 'i';
    $values[] = $userId;
    $stmt = $db->prepare($sql);
    $stmt->bind_param($types, ...$values);
    $stmt->execute();
    send_success('更新成功');
}

function dev_create_card_for_api($params, $currentDev) {
    $apiKey = trim($params['api_key'] ?? '');
    $type = $params['card_type'] ?? '';
    $points = intval($params['points'] ?? 0);
    $vipDays = intval($params['vip_days'] ?? 0);
    $expireDays = intval($params['expire_days'] ?? 30);
    if (empty($apiKey) || !in_array($type, ['api_user_integral','api_user_vip'])) send_error('参数错误');
    $db = getDB();
    $check = $db->prepare("SELECT id FROM apis WHERE api_key = ? AND developer_id = ?");
    $check->bind_param('si', $apiKey, $currentDev['id']);
    $check->execute();
    $api = $check->get_result()->fetch_assoc();
    if (!$api) send_error('API 不存在或不属于你');

    $cardCode = generateRandomKey(32);
    $expireTime = date('Y-m-d H:i:s', strtotime("+$expireDays days"));
    $stmt = $db->prepare("INSERT INTO cards (card_code, card_type, target_id, points, vip_days, expire_time) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param('ssiiis', $cardCode, $type, $api['id'], $points, $vipDays, $expireTime);
    $stmt->execute();
    send_success('卡密生成成功', ['card_code' => $cardCode]);
}

function dev_list_api_cards($params, $currentDev) {
    $apiKey = trim($params['api_key'] ?? '');
    if (empty($apiKey)) send_error('缺少 api_key');
    $db = getDB();
    $check = $db->prepare("SELECT id FROM apis WHERE api_key = ? AND developer_id = ?");
    $check->bind_param('si', $apiKey, $currentDev['id']);
    $check->execute();
    $api = $check->get_result()->fetch_assoc();
    if (!$api) send_error('API 不存在或不属于你');
    $stmt = $db->prepare("SELECT id, card_code, card_type, points, vip_days, used_by_id, used_at, expire_time, created_at FROM cards WHERE target_id = ? AND card_type IN ('api_user_integral','api_user_vip')");
    $stmt->bind_param('i', $api['id']);
    $stmt->execute();
    $cards = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    send_success(null, $cards);
}

function dev_create_doc($params, $currentDev) {
    $title = trim($params['title'] ?? '');
    $content = $params['content'] ?? '';
    if (empty($title)) send_error('标题不能为空');
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO documents (owner_type, owner_id, title, content) VALUES ('developer', ?, ?, ?)");
    $stmt->bind_param('iss', $currentDev['id'], $title, $content);
    $stmt->execute();
    $docId = $stmt->insert_id;
    $docUrl = SITE_URL . "/doc.php?id=" . $docId;
    send_success('文档创建成功', ['doc_id' => $docId, 'doc_url' => $docUrl]);
}

function dev_update_doc($params, $currentDev) {
    $docId = intval($params['doc_id'] ?? 0);
    $title = $params['title'] ?? null;
    $content = $params['content'] ?? null;
    if (!$docId) send_error('缺少 doc_id');
    $db = getDB();
    $check = $db->prepare("SELECT id FROM documents WHERE id = ? AND owner_type = 'developer' AND owner_id = ?");
    $check->bind_param('ii', $docId, $currentDev['id']);
    $check->execute();
    if ($check->get_result()->num_rows == 0) send_error('文档不存在或无权修改');
    $updates = [];
    $types = '';
    $values = [];
    if ($title !== null) {
        $updates[] = "title = ?";
        $types .= 's';
        $values[] = $title;
    }
    if ($content !== null) {
        $updates[] = "content = ?";
        $types .= 's';
        $values[] = $content;
    }
    if (empty($updates)) send_error('没有修改内容');
    $sql = "UPDATE documents SET " . implode(',', $updates) . " WHERE id = ?";
    $types .= 'i';
    $values[] = $docId;
    $stmt = $db->prepare($sql);
    $stmt->bind_param($types, ...$values);
    $stmt->execute();
    send_success('文档更新成功');
}

function dev_delete_doc($params, $currentDev) {
    $docId = intval($params['doc_id'] ?? 0);
    if (!$docId) send_error('缺少 doc_id');
    $db = getDB();
    $stmt = $db->prepare("DELETE FROM documents WHERE id = ? AND owner_type = 'developer' AND owner_id = ?");
    $stmt->bind_param('ii', $docId, $currentDev['id']);
    $stmt->execute();
    if ($stmt->affected_rows > 0) send_success('删除成功');
    else send_error('文档不存在或无权删除');
}

function dev_list_docs($params, $currentDev) {
    $db = getDB();
    $stmt = $db->prepare("SELECT id, title, content, created_at, updated_at FROM documents WHERE owner_type = 'developer' AND owner_id = ? ORDER BY id DESC");
    $stmt->bind_param('i', $currentDev['id']);
    $stmt->execute();
    $docs = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    foreach ($docs as &$doc) {
        $doc['doc_url'] = SITE_URL . "/doc.php?id=" . $doc['id'];
    }
    send_success(null, $docs);
}

// ----------------------------- API 用户端 -----------------------------
function apiuser_register($params) {
    $apiKey = $params['api_key'] ?? '';
    $username = trim($params['username'] ?? '');
    $password = $params['password'] ?? '';
    $email = $params['email'] ?? '';
    if (empty($apiKey) || empty($username) || empty($password)) send_error('缺少必要参数');
    $db = getDB();
    $api = getApiByKey($apiKey);
    if (!$api) send_error('无效的 API Key');
    if (isBanned($api['developer_ban_time'])) send_error('开发者已被封禁，无法注册');
    $check = $db->prepare("SELECT id FROM api_users WHERE api_id = ? AND username = ?");
    $check->bind_param('is', $api['id'], $username);
    $check->execute();
    if ($check->get_result()->num_rows > 0) send_error('用户名在该 API 下已存在');

    $userKey = generateRandomKey(64);
    $hashed = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $db->prepare("INSERT INTO api_users (api_id, username, password, user_key, email, integral) VALUES (?, ?, ?, ?, ?, 0)");
    $stmt->bind_param('issss', $api['id'], $username, $hashed, $userKey, $email);
    if ($stmt->execute()) {
        send_success('注册成功');
    } else {
        send_error('注册失败');
    }
}

function apiuser_login($params) {
    $apiKey = $params['api_key'] ?? '';
    $username = $params['username'] ?? '';
    $password = $params['password'] ?? '';
    if (empty($apiKey) || empty($username) || empty($password)) send_error('参数不完整');
    $db = getDB();
    $api = getApiByKey($apiKey);
    if (!$api) send_error('无效的 API Key');
    $stmt = $db->prepare("SELECT u.* FROM api_users u WHERE u.api_id = ? AND u.username = ?");
    $stmt->bind_param('is', $api['id'], $username);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    if (!$user || !password_verify($password, $user['password'])) send_error('用户名或密码错误');
    if (isBanned($user['ban_time'])) send_error('账号已被封禁');
    send_success('登录成功', ['user_key' => $user['user_key']]);
}

function apiuser_change_password($params, $currentApiUser) {
    $oldPass = $params['old_password'] ?? '';
    $newPass = $params['new_password'] ?? '';
    if (empty($oldPass) || empty($newPass)) send_error('原密码和新密码不能为空');
    $db = getDB();
    $stmt = $db->prepare("SELECT password FROM api_users WHERE id = ?");
    $stmt->bind_param('i', $currentApiUser['id']);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    if (!password_verify($oldPass, $row['password'])) send_error('原密码错误');
    $newHash = password_hash($newPass, PASSWORD_DEFAULT);
    $upd = $db->prepare("UPDATE api_users SET password = ? WHERE id = ?");
    $upd->bind_param('si', $newHash, $currentApiUser['id']);
    $upd->execute();
    send_success('密码修改成功');
}

function apiuser_redeem_card($params, $currentApiUser) {
    $code = trim($params['card_code'] ?? '');
    if (empty($code)) send_error('卡密不能为空');
    $db = getDB();
    $stmt = $db->prepare("SELECT * FROM cards WHERE card_code = ? AND used_by_id IS NULL AND (expire_time IS NULL OR expire_time > NOW()) AND card_type IN ('api_user_integral','api_user_vip') AND (target_id IS NULL OR target_id = ?)");
    $stmt->bind_param('si', $code, $currentApiUser['api_id']);
    $stmt->execute();
    $card = $stmt->get_result()->fetch_assoc();
    if (!$card) send_error('无效或已使用的卡密');

    $db->begin_transaction();
    try {
        if ($card['card_type'] == 'api_user_integral') {
            $points = intval($card['points']);
            $upd = $db->prepare("UPDATE api_users SET integral = integral + ? WHERE id = ?");
            $upd->bind_param('ii', $points, $currentApiUser['id']);
            $upd->execute();
        } else {
            $days = intval($card['vip_days']);
            $newVipTime = date('Y-m-d H:i:s', strtotime("+$days days"));
            $upd = $db->prepare("UPDATE api_users SET vip_time = ? WHERE id = ?");
            $upd->bind_param('si', $newVipTime, $currentApiUser['id']);
            $upd->execute();
        }
        $used = $db->prepare("UPDATE cards SET used_by_id = ?, used_at = NOW() WHERE id = ?");
        $used->bind_param('ii', $currentApiUser['id'], $card['id']);
        $used->execute();
        $db->commit();
        send_success('兑换成功');
    } catch (Exception $e) {
        $db->rollback();
        send_error('兑换失败');
    }
}

function apiuser_profile($params, $currentApiUser) {
    // 只返回 username, integral, vip_time, ban_time，不返回 api_key 等敏感信息
    $safe = [
        'username' => $currentApiUser['username'],
        'integral' => $currentApiUser['integral'],
        'vip_time' => $currentApiUser['vip_time'],
        'ban_time' => $currentApiUser['ban_time']
    ];
    send_success(null, $safe);
}

// ----------------------------- 超级管理员端 -----------------------------
function admin_login($params) {
    $username = trim($params['username'] ?? '');
    $password = $params['password'] ?? '';
    if (empty($username) || empty($password)) send_error('用户名密码不能为空');
    $db = getDB();
    $stmt = $db->prepare("SELECT id, username, userkey, password, is_admin FROM developers WHERE username = ? AND is_admin = 1");
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $admin = $stmt->get_result()->fetch_assoc();
    if (!$admin || !password_verify($password, $admin['password'])) send_error('管理员账号或密码错误');
    send_success('登录成功', ['userkey' => $admin['userkey']]);
}

function admin_register($params, $currentAdmin) {
    if (!$currentAdmin['is_admin']) send_error('无权限');
    $username = trim($params['username'] ?? '');
    $password = $params['password'] ?? '';
    $email = trim($params['email_address'] ?? '');
    if (empty($username) || empty($password)) send_error('参数不足');
    $db = getDB();
    $check = $db->prepare("SELECT id FROM developers WHERE username = ?");
    $check->bind_param('s', $username);
    $check->execute();
    if ($check->get_result()->num_rows > 0) send_error('用户名已存在');
    $userkey = generateRandomKey(64);
    $hashed = password_hash($password, PASSWORD_DEFAULT);
    $is_admin = 1;
    $stmt = $db->prepare("INSERT INTO developers (username, userkey, password, email_address, is_admin) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param('ssssi', $username, $userkey, $hashed, $email, $is_admin);
    $stmt->execute();
    send_success('管理员创建成功', ['userkey' => $userkey]);
}

function admin_ban_developer($params, $currentAdmin) {
    if (!$currentAdmin['is_admin']) send_error('无权限');
    $devId = intval($params['developer_id'] ?? 0);
    $banUntil = $params['ban_time'] ?? null;
    if (!$devId) send_error('缺少 developer_id');
    $db = getDB();
    $stmt = $db->prepare("UPDATE developers SET ban_time = ? WHERE id = ?");
    $stmt->bind_param('si', $banUntil, $devId);
    $stmt->execute();
    send_success('操作成功');
}

function admin_set_dev_vip($params, $currentAdmin) {
    if (!$currentAdmin['is_admin']) send_error('无权限');
    $devId = intval($params['developer_id'] ?? 0);
    $vipTime = $params['vip_time'] ?? null;
    if (!$devId) send_error('缺少 developer_id');
    $db = getDB();
    $stmt = $db->prepare("UPDATE developers SET vip_time = ? WHERE id = ?");
    $stmt->bind_param('si', $vipTime, $devId);
    $stmt->execute();
    send_success('操作成功');
}

function admin_create_card($params, $currentAdmin) {
    if (!$currentAdmin['is_admin']) send_error('无权限');
    $type = $params['card_type'] ?? '';
    $targetId = $params['target_id'] ?? null;
    $points = intval($params['points'] ?? 0);
    $vipDays = intval($params['vip_days'] ?? 0);
    $expireDays = intval($params['expire_days'] ?? 30);
    if (!in_array($type, ['developer_integral','developer_vip'])) send_error('无效卡密类型，管理员只能创建开发者卡密');
    $cardCode = generateRandomKey(32);
    $expireTime = date('Y-m-d H:i:s', strtotime("+$expireDays days"));
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO cards (card_code, card_type, target_id, points, vip_days, expire_time) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param('ssiiis', $cardCode, $type, $targetId, $points, $vipDays, $expireTime);
    $stmt->execute();
    send_success('卡密生成成功', ['card_code' => $cardCode]);
}

function admin_create_doc($params, $currentAdmin) {
    if (!$currentAdmin['is_admin']) send_error('无权限');
    $title = trim($params['title'] ?? '');
    $content = $params['content'] ?? '';
    $ownerId = intval($params['owner_id'] ?? 0);
    if (empty($title)) send_error('标题不能为空');
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO documents (owner_type, owner_id, title, content) VALUES ('admin', ?, ?, ?)");
    $stmt->bind_param('iss', $ownerId, $title, $content);
    $stmt->execute();
    $docId = $stmt->insert_id;
    $docUrl = SITE_URL . "/doc.php?id=" . $docId;
    send_success('文档创建成功', ['doc_id' => $docId, 'doc_url' => $docUrl]);
}

function admin_update_doc($params, $currentAdmin) {
    if (!$currentAdmin['is_admin']) send_error('无权限');
    $docId = intval($params['doc_id'] ?? 0);
    $title = $params['title'] ?? null;
    $content = $params['content'] ?? null;
    if (!$docId) send_error('缺少 doc_id');
    $db = getDB();
    $stmt = $db->prepare("SELECT id FROM documents WHERE id = ? AND owner_type = 'admin'");
    $stmt->bind_param('i', $docId);
    $stmt->execute();
    if ($stmt->get_result()->num_rows == 0) send_error('文档不存在或无权修改');
    $updates = [];
    $types = '';
    $values = [];
    if ($title !== null) {
        $updates[] = "title = ?";
        $types .= 's';
        $values[] = $title;
    }
    if ($content !== null) {
        $updates[] = "content = ?";
        $types .= 's';
        $values[] = $content;
    }
    if (empty($updates)) send_error('没有修改内容');
    $sql = "UPDATE documents SET " . implode(',', $updates) . " WHERE id = ?";
    $types .= 'i';
    $values[] = $docId;
    $updStmt = $db->prepare($sql);
    $updStmt->bind_param($types, ...$values);
    $updStmt->execute();
    send_success('文档更新成功');
}

function admin_delete_doc($params, $currentAdmin) {
    if (!$currentAdmin['is_admin']) send_error('无权限');
    $docId = intval($params['doc_id'] ?? 0);
    if (!$docId) send_error('缺少 doc_id');
    $db = getDB();
    $stmt = $db->prepare("DELETE FROM documents WHERE id = ? AND owner_type = 'admin'");
    $stmt->bind_param('i', $docId);
    $stmt->execute();
    if ($stmt->affected_rows > 0) send_success('删除成功');
    else send_error('文档不存在或无权删除');
}

function admin_list_docs($params, $currentAdmin) {
    if (!$currentAdmin['is_admin']) send_error('无权限');
    $db = getDB();
    $stmt = $db->prepare("SELECT id, owner_id, title, content, created_at, updated_at FROM documents WHERE owner_type = 'admin' ORDER BY id DESC");
    $stmt->execute();
    $docs = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    foreach ($docs as &$doc) {
        $doc['doc_url'] = SITE_URL . "/doc.php?id=" . $doc['id'];
    }
    send_success(null, $docs);
}

// ----------------------------- 主路由 -----------------------------
$params = getParams();
if (empty($params) || !isset($params['action'])) {
    send_error('缺少 action 参数');
}
$action = $params['action'];

$publicActions = [
    'dev_register', 'dev_login',
    'apiuser_register', 'apiuser_login',
    'admin_login'
];
if (in_array($action, $publicActions)) {
    switch ($action) {
        case 'dev_register': dev_register($params); break;
        case 'dev_login': dev_login($params); break;
        case 'apiuser_register': apiuser_register($params); break;
        case 'apiuser_login': apiuser_login($params); break;
        case 'admin_login': admin_login($params); break;
        default: send_error('未知操作');
    }
}

if (isset($params['userkey']) && !empty($params['userkey'])) {
    $currentDev = getDeveloperByUserkey($params['userkey']);
    if ($currentDev) {
        switch ($action) {
            case 'dev_reset_userkey': dev_reset_userkey($params, $currentDev); break;
            case 'dev_change_password': dev_change_password($params, $currentDev); break;
            case 'dev_redeem_card': dev_redeem_card($params, $currentDev); break;
            case 'dev_profile': dev_profile($params, $currentDev); break;
            case 'dev_create_api': dev_create_api($params, $currentDev); break;
            case 'dev_reset_apikey': dev_reset_apikey($params, $currentDev); break;
            case 'dev_list_apis': dev_list_apis($params, $currentDev); break;
            case 'dev_list_api_users': dev_list_api_users($params, $currentDev); break;
            case 'dev_modify_user_integral': dev_modify_user_integral($params, $currentDev); break;
            case 'dev_set_user_time': dev_set_user_time($params, $currentDev); break;
            case 'dev_create_card_for_api': dev_create_card_for_api($params, $currentDev); break;
            case 'dev_list_api_cards': dev_list_api_cards($params, $currentDev); break;
            case 'dev_create_doc': dev_create_doc($params, $currentDev); break;
            case 'dev_update_doc': dev_update_doc($params, $currentDev); break;
            case 'dev_delete_doc': dev_delete_doc($params, $currentDev); break;
            case 'dev_list_docs': dev_list_docs($params, $currentDev); break;
            // 管理员操作（仅当该用户是管理员时有效）
            case 'admin_register': admin_register($params, $currentDev); break;
            case 'admin_ban_developer': admin_ban_developer($params, $currentDev); break;
            case 'admin_set_dev_vip': admin_set_dev_vip($params, $currentDev); break;
            case 'admin_create_card': admin_create_card($params, $currentDev); break;
            case 'admin_create_doc': admin_create_doc($params, $currentDev); break;
            case 'admin_update_doc': admin_update_doc($params, $currentDev); break;
            case 'admin_delete_doc': admin_delete_doc($params, $currentDev); break;
            case 'admin_list_docs': admin_list_docs($params, $currentDev); break;
            default: send_error('未知操作或权限不足');
        }
        exit;
    }
}

if (isset($params['user_key']) && !empty($params['user_key'])) {
    $currentApiUser = getApiUserByUserKey($params['user_key']);
    if ($currentApiUser) {
        if (isBanned($currentApiUser['ban_time'])) send_error('用户已被封禁');
        switch ($action) {
            case 'apiuser_change_password': apiuser_change_password($params, $currentApiUser); break;
            case 'apiuser_redeem_card': apiuser_redeem_card($params, $currentApiUser); break;
            case 'apiuser_profile': apiuser_profile($params, $currentApiUser); break;
            default: send_error('未知用户操作');
        }
        exit;
    }
}

send_error('认证失败，请提供有效的 userkey 或 user_key');
?>