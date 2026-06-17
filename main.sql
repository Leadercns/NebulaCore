CREATE TABLE `developers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `userkey` varchar(64) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email_address` varchar(128) NOT NULL,
  `vip_time` datetime DEFAULT NULL,
  `ban_time` datetime DEFAULT NULL,
  `integral` int(11) NOT NULL DEFAULT 0,
  `is_admin` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email_address` (`email_address`),
  UNIQUE KEY `userkey` (`userkey`)
);

CREATE TABLE `apis` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `developer_id` int(11) NOT NULL,
  `api_name` TEXT NOT NULL,
  `api_key` varchar(64) NOT NULL,
  `api_secret` varchar(64) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `api_key` (`api_key`),
  KEY `developer_id` (`developer_id`),
  CONSTRAINT `apis_ibfk_1` FOREIGN KEY (`developer_id`) REFERENCES `developers` (`id`) ON DELETE CASCADE
);

CREATE TABLE `api_users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `api_id` int(11) NOT NULL,
  `username` varchar(64) NOT NULL,
  `password` varchar(255) NOT NULL,
  `user_key` varchar(64) NOT NULL,
  `email` varchar(128) DEFAULT NULL,
  `integral` int(11) NOT NULL DEFAULT 0,
  `vip_time` datetime DEFAULT NULL,
  `ban_time` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username_per_api` (`api_id`,`username`),
  UNIQUE KEY `user_key` (`user_key`),
  KEY `api_id` (`api_id`),
  CONSTRAINT `api_users_ibfk_1` FOREIGN KEY (`api_id`) REFERENCES `apis` (`id`) ON DELETE CASCADE
);

CREATE TABLE `cards` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `card_code` varchar(64) NOT NULL,
  `card_type` enum('developer_integral','developer_vip','api_user_integral','api_user_vip') NOT NULL,
  `target_id` int(11) DEFAULT NULL,
  `points` int(11) DEFAULT NULL,
  `vip_days` int(11) DEFAULT NULL,
  `used_by_id` int(11) DEFAULT NULL,
  `used_at` datetime DEFAULT NULL,
  `expire_time` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `card_code` (`card_code`)
);

CREATE TABLE `documents` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `owner_type` enum('developer','admin') NOT NULL,
  `owner_id` int(11) NOT NULL,
  `title` TEXT NOT NULL,
  `content` text,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `owner` (`owner_type`,`owner_id`)
);