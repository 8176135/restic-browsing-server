/*
 Navicat Premium Data Transfer

 Source Server         : TestingDb
 Source Server Type    : MariaDB
 Source Server Version : 100137
 Source Host           : localhost:3306
 Source Schema         : ResticOnlineAccounts

 Target Server Type    : MariaDB
 Target Server Version : 100137
 File Encoding         : 65001

 Date: 29/01/2019 20:42:32
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for Announcements
-- ----------------------------
DROP TABLE IF EXISTS `Announcements`;
CREATE TABLE `Announcements`  (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `displayed` tinyint(1) NOT NULL,
  `title` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `contents` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Table structure for AuthRepoPasswords
-- ----------------------------
DROP TABLE IF EXISTS `AuthRepoPasswords`;
CREATE TABLE `AuthRepoPasswords`  (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `owning_user` int(10) UNSIGNED NOT NULL,
  `auth_repo_enc_pass` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `expiry_date` datetime(0) NOT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `arp_ou_fk`(`owning_user`) USING BTREE,
  CONSTRAINT `arp_ou_fk` FOREIGN KEY (`owning_user`) REFERENCES `Users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE = InnoDB AUTO_INCREMENT = 5 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Table structure for ConnectionInfo
-- ----------------------------
DROP TABLE IF EXISTS `ConnectionInfo`;
CREATE TABLE `ConnectionInfo`  (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `owning_user` int(10) UNSIGNED NOT NULL,
  `name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `encryption_password` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NULL DEFAULT NULL,
  `service_used` int(10) UNSIGNED NOT NULL,
  `path` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `user_name_UNIQUE`(`owning_user`, `name`(50)) USING BTREE,
  INDEX `con_info_fk_idx`(`owning_user`) USING BTREE,
  INDEX `con_info_su_fk`(`service_used`) USING BTREE,
  CONSTRAINT `con_info_ou_fk` FOREIGN KEY (`owning_user`) REFERENCES `Users` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `con_info_su_fk` FOREIGN KEY (`service_used`) REFERENCES `Services` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 42 CHARACTER SET = utf8 COLLATE = utf8_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for EnvNames
-- ----------------------------
DROP TABLE IF EXISTS `EnvNames`;
CREATE TABLE `EnvNames`  (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `env_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `env_name_UNIQUE`(`env_name`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 37 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Table structure for ServiceContents
-- ----------------------------
DROP TABLE IF EXISTS `ServiceContents`;
CREATE TABLE `ServiceContents`  (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `env_name_id` int(10) UNSIGNED NOT NULL,
  `owning_service` int(10) UNSIGNED NOT NULL,
  `encrypted_env_value` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `owning_preset_env_id_unique`(`env_name_id`, `owning_service`) USING BTREE,
  INDEX `contents_os_fk`(`owning_service`) USING BTREE,
  CONSTRAINT `contents_os_fk` FOREIGN KEY (`owning_service`) REFERENCES `Services` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `env_name_fk` FOREIGN KEY (`env_name_id`) REFERENCES `EnvNames` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 27 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Table structure for ServiceType
-- ----------------------------
DROP TABLE IF EXISTS `ServiceType`;
CREATE TABLE `ServiceType`  (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `service_type` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 8 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Table structure for Services
-- ----------------------------
DROP TABLE IF EXISTS `Services`;
CREATE TABLE `Services`  (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `owning_user` int(10) UNSIGNED NOT NULL,
  `service_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `service_type` int(10) UNSIGNED NOT NULL DEFAULT 1,
  `enc_addr_part` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `PresetName_Uq`(`owning_user`, `service_name`(50)) USING BTREE,
  INDEX `preset_user_Idx`(`owning_user`) USING BTREE,
  INDEX `preset_st_fk`(`service_type`) USING BTREE,
  CONSTRAINT `preset_st_fk` FOREIGN KEY (`service_type`) REFERENCES `ServiceType` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT `service_ou_fk` FOREIGN KEY (`owning_user`) REFERENCES `Users` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 14 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Table structure for Users
-- ----------------------------
DROP TABLE IF EXISTS `Users`;
CREATE TABLE `Users`  (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` varchar(128) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `email` varchar(128) CHARACTER SET utf8 COLLATE utf8_unicode_ci NULL DEFAULT NULL,
  `password` char(128) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `salt` varchar(32) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `enced_enc_pass` char(128) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `kilobytes_downloaded` int(10) NOT NULL DEFAULT 0,
  `activation_code` varchar(128) CHARACTER SET utf8 COLLATE utf8_unicode_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `username_UNIQUE`(`username`) USING BTREE,
  UNIQUE INDEX `email_UNIQUE`(`email`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 19 CHARACTER SET = utf8 COLLATE = utf8_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- View structure for BasesList
-- ----------------------------
DROP VIEW IF EXISTS `BasesList`;
CREATE ALGORITHM = UNDEFINED SQL SECURITY DEFINER VIEW `BasesList` AS select `Services`.`owning_user` AS `owning_user`,`Services`.`service_name` AS `service_name`,`Services`.`service_type` AS `service_type`,group_concat(`ServiceContents`.`env_name_id` separator ',') AS `env_name_ids`,group_concat(`ServiceContents`.`encrypted_env_value` separator ',') AS `encrypted_env_values`,`Services`.`enc_addr_part` AS `enc_addr_part` from (`Services` left join `ServiceContents` on((`ServiceContents`.`owning_service` = `Services`.`id`))) group by `Services`.`service_name`;

-- ----------------------------
-- View structure for QueryView
-- ----------------------------
DROP VIEW IF EXISTS `QueryView`;
CREATE ALGORITHM = UNDEFINED SQL SECURITY DEFINER VIEW `QueryView` AS select `ConnectionInfo`.`name` AS `name`,`ConnectionInfo`.`path` AS `path`,`ConnectionInfo`.`owning_user` AS `owning_user`,`ConnectionInfo`.`encryption_password` AS `encryption_password`,`Services`.`service_name` AS `service_name`,`ServiceContents`.`encrypted_env_value` AS `encrypted_env_value`,`EnvNames`.`env_name` AS `env_name`,`ServiceType`.`service_type` AS `service_type`,`Services`.`enc_addr_part` AS `enc_addr_part` from ((((`ConnectionInfo` join `Services` on((`ConnectionInfo`.`service_used` = `Services`.`id`))) left join `ServiceContents` on((`Services`.`id` = `ServiceContents`.`owning_service`))) left join `EnvNames` on((`ServiceContents`.`env_name_id` = `EnvNames`.`id`))) join `ServiceType` on((`Services`.`service_type` = `ServiceType`.`id`)));

-- ----------------------------
-- Function structure for update_repositories
-- ----------------------------
DROP FUNCTION IF EXISTS `update_repositories`;
delimiter ;;
CREATE FUNCTION `update_repositories`(serviceName VARCHAR(64), owningUser INT, repoName VARCHAR(64), oldRepoName VARCHAR(64), newPath VARCHAR(255), encryptionPassword VARCHAR(255))
 RETURNS int(5)
BEGIN
	#Routine body goes here...
	DECLARE service_id INT DEFAULT 0;
	SELECT id INTO service_id FROM Services WHERE Services.service_name=serviceName COLLATE utf8mb4_unicode_ci;
	
	INSERT INTO ConnectionInfo (
	ConnectionInfo.`name`, 
	ConnectionInfo.owning_user,
  ConnectionInfo.path,
	ConnectionInfo.service_used, 
	ConnectionInfo.encryption_password) 
	VALUES (
	oldRepoName COLLATE utf8mb4_unicode_ci,
	owningUser, 
	newPath,
	service_id, 
	encryptionPassword) 
	ON DUPLICATE KEY UPDATE 
	ConnectionInfo.`name`=repoName COLLATE utf8mb4_unicode_ci, 
	ConnectionInfo.service_used=service_id, 
	ConnectionInfo.path=newPath,
	ConnectionInfo.encryption_password=IFNULL(encryptionPassword,ConnectionInfo.encryption_password);
	
	RETURN 0;
END
;;
delimiter ;

-- ----------------------------
-- Event structure for ExpiredPassRemover
-- ----------------------------
DROP EVENT IF EXISTS `ExpiredPassRemover`;
delimiter ;;
CREATE EVENT `ExpiredPassRemover`
ON SCHEDULE
EVERY '1' DAY STARTS '2018-12-23 20:30:00'
ON COMPLETION PRESERVE
DO DELETE FROM AuthRepoPasswords WHERE AuthRepoPasswords.expiry_date < NOW()
;;
delimiter ;

-- ----------------------------
-- Event structure for ResetDataUsed
-- ----------------------------
DROP EVENT IF EXISTS `ResetDataUsed`;
delimiter ;;
CREATE EVENT `ResetDataUsed`
ON SCHEDULE
EVERY '1' DAY STARTS '2018-12-23 20:30:00'
ON COMPLETION PRESERVE
DO UPDATE Users SET Users.kilobytes_downloaded=0
;;
delimiter ;

SET FOREIGN_KEY_CHECKS = 1;
