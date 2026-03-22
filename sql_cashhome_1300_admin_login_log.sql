-- 관리자 로그인 위치/접속 이력 테이블
-- 실행 순서:
-- 1) 기존 테이블이 있으면 삭제
-- 2) 신규 테이블 생성

DROP TABLE IF EXISTS cashhome_1300_admin_login_log;

CREATE TABLE cashhome_1300_admin_login_log (
    cashhome_1300_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '로그 PK',

    cashhome_1300_admin_db_id INT NOT NULL COMMENT '관리자 ID (master=1, admin=2)',
    cashhome_1300_admin_role VARCHAR(20) NOT NULL DEFAULT 'admin' COMMENT '관리자 권한',
    cashhome_1300_admin_username VARCHAR(50) NOT NULL DEFAULT '' COMMENT '관리자 표시명',

    cashhome_1300_login_status ENUM('SUCCESS', 'FAIL') NOT NULL DEFAULT 'SUCCESS' COMMENT '로그인 결과',
    cashhome_1300_login_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '로그인 시각',

    cashhome_1300_login_ip VARCHAR(45) NOT NULL DEFAULT '' COMMENT '접속 IP',
    cashhome_1300_user_agent VARCHAR(700) NOT NULL DEFAULT '' COMMENT 'User-Agent',
    cashhome_1300_device_type VARCHAR(20) NOT NULL DEFAULT 'web' COMMENT '디바이스 타입',
    cashhome_1300_browser VARCHAR(120) NOT NULL DEFAULT '' COMMENT '브라우저',
    cashhome_1300_os_name VARCHAR(120) NOT NULL DEFAULT '' COMMENT 'OS',

    cashhome_1300_country_code VARCHAR(8) NULL DEFAULT NULL COMMENT '국가코드',
    cashhome_1300_region_name VARCHAR(120) NULL DEFAULT NULL COMMENT '지역/도',
    cashhome_1300_city_name VARCHAR(120) NULL DEFAULT NULL COMMENT '도시',
    cashhome_1300_latitude DECIMAL(10,7) NULL DEFAULT NULL COMMENT '위도',
    cashhome_1300_longitude DECIMAL(10,7) NULL DEFAULT NULL COMMENT '경도',
    cashhome_1300_timezone_name VARCHAR(64) NULL DEFAULT NULL COMMENT '타임존',
    cashhome_1300_location_text VARCHAR(255) NULL DEFAULT NULL COMMENT '지도 표시 문자열',
    cashhome_1300_geo_source VARCHAR(40) NOT NULL DEFAULT '' COMMENT '위치 수집 소스',
    cashhome_1300_geo_status VARCHAR(40) NOT NULL DEFAULT '' COMMENT '위치 수집 상태',

    cashhome_1300_referer_url VARCHAR(1024) NULL DEFAULT NULL COMMENT 'HTTP Referer',
    cashhome_1300_request_uri VARCHAR(1024) NULL DEFAULT NULL COMMENT '요청 URI',

    cashhome_1300_created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '레코드 생성시각',

    PRIMARY KEY (cashhome_1300_id),
    KEY idx_cashhome_1300_admin_time (cashhome_1300_admin_db_id, cashhome_1300_login_at),
    KEY idx_cashhome_1300_login_time (cashhome_1300_login_at),
    KEY idx_cashhome_1300_login_status (cashhome_1300_login_status),
    KEY idx_cashhome_1300_login_ip (cashhome_1300_login_ip)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='관리자 로그인 접속/위치 이력';
