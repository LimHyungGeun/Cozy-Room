-- ============================================================
-- COZY ROOM Platform Database Initialization
-- Character set: UTF-8 (한글 지원)
-- ============================================================

SET NAMES utf8mb4;
SET character_set_client = utf8mb4;

CREATE DATABASE IF NOT EXISTS cozyroom
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE cozyroom;

-- ============================================================
-- 사용자 테이블
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(50)  NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    email       VARCHAR(100) NOT NULL UNIQUE,
    phone       VARCHAR(20),
    name        VARCHAR(50),
    birth_date  DATE,
    address     VARCHAR(200),
    profile_img VARCHAR(255) DEFAULT 'default_profile.png',
    is_admin    TINYINT(1)   DEFAULT 0,
    created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
    last_login  DATETIME
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 지역 테이블
-- ============================================================
CREATE TABLE IF NOT EXISTS regions (
    id      INT AUTO_INCREMENT PRIMARY KEY,
    name    VARCHAR(50) NOT NULL,
    slug    VARCHAR(50) NOT NULL UNIQUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 숙박 업체 테이블
-- ============================================================
CREATE TABLE IF NOT EXISTS hotels (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    name         VARCHAR(100) NOT NULL,
    region_id    INT,
    address      VARCHAR(200),
    description  TEXT,
    star_rating  TINYINT DEFAULT 3,
    thumbnail    VARCHAR(255),
    amenities    VARCHAR(500),
    check_in     TIME DEFAULT '15:00:00',
    check_out    TIME DEFAULT '11:00:00',
    is_premium   TINYINT(1) DEFAULT 0,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (region_id) REFERENCES regions(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 객실 테이블
-- ============================================================
CREATE TABLE IF NOT EXISTS rooms (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    hotel_id     INT NOT NULL,
    room_type    VARCHAR(50) NOT NULL,
    room_name    VARCHAR(100) NOT NULL,
    price        INT NOT NULL,
    capacity     TINYINT DEFAULT 2,
    bed_type     VARCHAR(50),
    size_m2      INT,
    description  TEXT,
    thumbnail    VARCHAR(255),
    is_available TINYINT(1) DEFAULT 1,
    FOREIGN KEY (hotel_id) REFERENCES hotels(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 예약 테이블
-- ============================================================
CREATE TABLE IF NOT EXISTS bookings (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    booking_code   VARCHAR(20) NOT NULL UNIQUE,
    user_id        INT NOT NULL,
    room_id        INT NOT NULL,
    guest_name     VARCHAR(50) NOT NULL,
    guest_phone    VARCHAR(20) NOT NULL,
    check_in_date  DATE NOT NULL,
    check_out_date DATE NOT NULL,
    nights         INT NOT NULL,
    total_price    INT NOT NULL,
    special_req    TEXT,
    status         ENUM('대기','확정','취소','완료') DEFAULT '대기',
    payment_method VARCHAR(30),
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (room_id) REFERENCES rooms(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 리뷰 테이블 (status 컬럼 추가 — 관리자 검토 워크플로우)
-- ============================================================
CREATE TABLE IF NOT EXISTS reviews (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    booking_id  INT NOT NULL,
    user_id     INT NOT NULL,
    hotel_id    INT NOT NULL,
    rating      TINYINT NOT NULL,
    title       VARCHAR(100),
    content     TEXT,
    image_path  VARCHAR(255),
    status      ENUM('pending','approved','rejected') DEFAULT 'pending',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (hotel_id) REFERENCES hotels(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 쿠폰 테이블
-- ============================================================
CREATE TABLE IF NOT EXISTS coupons (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    code         VARCHAR(30) NOT NULL UNIQUE,
    discount_pct INT DEFAULT 10,
    valid_until  DATE,
    is_used      TINYINT(1) DEFAULT 0,
    used_by      INT,
    FOREIGN KEY (used_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- SMS 발송 로그 테이블
-- ============================================================
CREATE TABLE IF NOT EXISTS sms_logs (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT,
    phone      VARCHAR(20),
    message    TEXT,
    sent_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    status     VARCHAR(20) DEFAULT 'sent'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 파일 업로드 로그
-- ============================================================
CREATE TABLE IF NOT EXISTS uploads (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT,
    filename    VARCHAR(255),
    orig_name   VARCHAR(255),
    file_path   VARCHAR(500),
    upload_at   DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 데이터 삽입: 지역
-- ============================================================
INSERT INTO regions (name, slug) VALUES
('서울', 'seoul'),
('부산', 'busan'),
('제주', 'jeju'),
('강릉', 'gangneung'),
('경주', 'gyeongju'),
('여수', 'yeosu'),
('가평', 'gapyeong'),
('전주', 'jeonju');

-- ============================================================
-- 데이터 삽입: 호텔
-- ============================================================
INSERT INTO hotels (name, region_id, address, description, star_rating, thumbnail, amenities, is_premium) VALUES
('그랜드 하얏트 서울', 1, '서울특별시 용산구 소월로 322', '남산 뷰를 품은 최고급 5성 호텔. 아시아 최대 규모의 피트니스 센터와 루프탑 풀을 자랑합니다.', 5, 'https://images.unsplash.com/photo-1566073771259-6a8506099945?w=600&q=80', '수영장,피트니스,스파,레스토랑,주차장,와이파이', 1),
('파라다이스 호텔 부산', 2, '부산광역시 해운대구 해운대해변로 296', '해운대 해변을 품은 프리미엄 리조트 호텔. 카지노와 스파를 함께 즐길 수 있습니다.', 5, 'https://images.unsplash.com/photo-1520250497591-112f2f40a3f4?w=600&q=80', '카지노,스파,수영장,레스토랑,비즈니스센터,주차장', 1),
('롯데 호텔 제주', 3, '제주특별자치도 서귀포시 중문관광로72번길 35', '한라산과 바다가 한눈에 보이는 제주 최고의 럭셔리 리조트입니다.', 5, 'https://images.unsplash.com/photo-1506929562872-bb421503ef21?w=600&q=80', '골프장,수영장,스파,레스토랑,제주흑돼지,주차장', 1),
('씨마크 호텔 강릉', 4, '강원특별자치도 강릉시 창해로 307', '동해 바다를 전면으로 바라보는 오션뷰 호텔. 강릉 커피거리와 인접해 있습니다.', 4, 'https://images.unsplash.com/photo-1455587734955-081b22074882?w=600&q=80', '오션뷰,수영장,피트니스,레스토랑,카페,주차장', 0),
('라한셀렉트 경주', 5, '경북 경주시 보문로 400-2', '신라 천년의 역사가 살아 숨쉬는 보문관광단지 내 프리미엄 호텔입니다.', 4, 'https://images.unsplash.com/photo-1551882547-ff40c63fe5fa?w=600&q=80', '한옥체험,수영장,스파,온천,레스토랑,주차장', 0),
('베네치아 호텔 여수', 6, '전남 여수시 오동도로 116', '밤바다의 낭만과 함께하는 여수 엑스포 인근 오션뷰 호텔입니다.', 4, 'https://images.unsplash.com/photo-1542314831-068cd1dbfeeb?w=600&q=80', '오션뷰,수영장,레스토랑,루프탑바,주차장', 0),
('쁘띠프랑스 펜션 가평', 7, '경기도 가평군 청평면 고성리 506-1', '남이섬과 가까운 프랑스 감성 프리미엄 펜션. 가족 여행객에게 인기 있습니다.', 3, 'https://images.unsplash.com/photo-1445019980597-93fa8acb246c?w=600&q=80', '바베큐,수영장,어린이놀이터,와이파이,주차장', 0),
('한옥 스테이 전주', 8, '전북 전주시 완산구 기린대로 75', '전통 한옥의 미를 현대적으로 재해석한 프리미엄 한옥 스테이입니다.', 4, 'https://images.unsplash.com/photo-1493976040374-85c8e12f0c0e?w=600&q=80', '한옥체험,비빔밥조식,전통차,한복체험,주차장', 0);

-- ============================================================
-- 데이터 삽입: 객실
-- ============================================================
INSERT INTO rooms (hotel_id, room_type, room_name, price, capacity, bed_type, size_m2, description, thumbnail) VALUES
(1, '스탠다드', '그랜드 디럭스 룸', 280000, 2, '킹사이즈', 45, '남산 전망의 모던한 디럭스 객실. 최고급 침구와 대리석 욕실이 특징입니다.', 'https://images.unsplash.com/photo-1631049307264-da0ec9d70304?w=600&q=80'),
(1, '스위트', '프레지덴셜 스위트', 1200000, 4, '킹사이즈 x2', 120, '최상층에 위치한 최고급 스위트룸. 서울 전경이 한눈에 펼쳐집니다.', 'https://images.unsplash.com/photo-1582719478250-c89cae4dc85b?w=600&q=80'),
(2, '스탠다드', '오션뷰 디럭스', 320000, 2, '킹사이즈', 50, '해운대 바다가 정면으로 보이는 오션뷰 객실입니다.', 'https://images.unsplash.com/photo-1590490360182-c33d57733427?w=600&q=80'),
(2, '스위트', '해운대 스위트', 850000, 4, '킹사이즈', 95, '해운대 전경을 파노라마로 감상할 수 있는 럭셔리 스위트룸입니다.', 'https://images.unsplash.com/photo-1618773928121-c32242e63f39?w=600&q=80'),
(3, '스탠다드', '가든뷰 디럭스', 260000, 2, '퀸사이즈', 42, '제주의 아름다운 정원이 내려다보이는 쾌적한 객실입니다.', 'https://images.unsplash.com/photo-1595526114035-0d45ed16cfbf?w=600&q=80'),
(3, '프리미엄', '제주 오션 스위트', 680000, 2, '킹사이즈', 80, '한라산과 제주 바다를 동시에 즐길 수 있는 프리미엄 스위트입니다.', 'https://images.unsplash.com/photo-1564501049412-61c2a3083791?w=600&q=80'),
(4, '스탠다드', '동해 오션뷰 룸', 200000, 2, '더블침대', 38, '동해 일출을 방에서 바라볼 수 있는 특별한 경험을 제공합니다.', 'https://images.unsplash.com/photo-1507652313519-d4e9174996dd?w=600&q=80'),
(5, '스탠다드', '신라 한옥 스탠다드', 180000, 2, '온돌', 35, '전통 신라 양식으로 꾸며진 온돌방입니다.', 'https://images.unsplash.com/photo-1611892440504-42a792e24d32?w=600&q=80'),
(6, '스탠다드', '여수 야경 룸', 190000, 2, '더블침대', 36, '여수 밤바다 야경을 즐길 수 있는 낭만적인 객실입니다.', 'https://images.unsplash.com/photo-1566195992011-5f6b21e539aa?w=600&q=80'),
(7, '스탠다드', '프렌치 가든 룸', 150000, 4, '트윈침대', 40, '프랑스 감성의 정원이 딸린 패밀리 룸입니다.', 'https://images.unsplash.com/photo-1584132967334-10e028bd69f7?w=600&q=80'),
(8, '스탠다드', '전통 한옥 온돌방', 170000, 2, '온돌', 33, '200년 된 고택을 현대적으로 복원한 전통 한옥 객실입니다.', 'https://images.unsplash.com/photo-1578683010236-d716f9a3f461?w=600&q=80');

-- ============================================================
-- 데이터 삽입: 관리자 계정 (비밀번호: CozyAdmin@2024!)
-- ============================================================
INSERT INTO users (username, password, email, phone, name, is_admin) VALUES
('admin', 'scrypt:32768:8:1$YqkatichHjIniwLy$a4afd3436cf9bccc9c343f3450d48d5d0b042c4cae6346702b1a3873f7d3030102170c6c6a07d93e7853d59fb5535624c0f0ff61d86599bd83ecbec756ed0616', 'admin@cozyroom.kr', '02-1234-5678', '관리자', 1);

-- ============================================================
-- 데이터 삽입: 샘플 사용자들 (비밀번호: CozyUser@2024!)
-- ============================================================
INSERT INTO users (username, password, email, phone, name, birth_date, address) VALUES
('kim_minjun', 'scrypt:32768:8:1$izzNF6kgISxqlJOU$50c1661a4052b68a9305b19bd657788413b1c886c72b5e0e92c80a97577809f969b0ca9fa7afe79581957a7e81d5ded88500fef202492b15cfb0787f65d49858', 'minjun.kim@naver.com', '010-1234-5678', '김민준', '1990-03-15', '서울특별시 강남구 역삼동 123'),
('park_soyeon', 'scrypt:32768:8:1$izzNF6kgISxqlJOU$50c1661a4052b68a9305b19bd657788413b1c886c72b5e0e92c80a97577809f969b0ca9fa7afe79581957a7e81d5ded88500fef202492b15cfb0787f65d49858', 'soyeon.park@kakao.com', '010-2345-6789', '박소연', '1995-07-22', '경기도 성남시 분당구 정자동 456'),
('lee_jiwon', 'scrypt:32768:8:1$izzNF6kgISxqlJOU$50c1661a4052b68a9305b19bd657788413b1c886c72b5e0e92c80a97577809f969b0ca9fa7afe79581957a7e81d5ded88500fef202492b15cfb0787f65d49858', 'jiwon.lee@gmail.com', '010-3456-7890', '이지원', '1988-11-08', '부산광역시 해운대구 우동 789');

-- ============================================================
-- 데이터 삽입: 샘플 쿠폰
-- ============================================================
INSERT INTO coupons (code, discount_pct, valid_until) VALUES
('COZY2024', 15, '2025-12-31'),
('WELCOME10', 10, '2025-12-31'),
('PREMIUM20', 20, '2025-06-30'),
('BUSAN15', 15, '2025-09-30');

-- ============================================================
-- 데이터 삽입: 샘플 예약 내역
-- ============================================================
INSERT INTO bookings (booking_code, user_id, room_id, guest_name, guest_phone, check_in_date, check_out_date, nights, total_price, status, payment_method) VALUES
('CR20240301001', 2, 1, '김민준', '010-1234-5678', '2024-03-10', '2024-03-12', 2, 560000, '완료', '신용카드'),
('CR20240315002', 3, 3, '박소연', '010-2345-6789', '2024-04-01', '2024-04-03', 2, 640000, '완료', '카카오페이'),
('CR20240320003', 4, 7, '이지원', '010-3456-7890', '2024-04-15', '2024-04-17', 2, 400000, '완료', '토스페이');

-- ============================================================
-- 데이터 삽입: 샘플 리뷰 (승인된 정상 리뷰)
-- ============================================================
INSERT INTO reviews (booking_id, user_id, hotel_id, rating, title, content, status) VALUES
(1, 2, 1, 5, '최고의 숙소', '남산 전망이 정말 아름다웠습니다. 객실도 깨끗하고 조식 뷔페도 훌륭했어요. 다음에 또 방문하고 싶습니다!', 'approved'),
(2, 3, 2, 4, '해운대 뷰가 멋져요', '해운대 해변이 한눈에 보여서 좋았습니다. 다만 주변 식당이 조금 비싼 편이었어요.', 'approved');

-- ============================================================
-- 데이터 삽입: SMS 발송 로그
-- ============================================================
INSERT INTO sms_logs (user_id, phone, message) VALUES
(2, '010-1234-5678', '[코지룸] 김민준님, CR20240301001 예약이 확정되었습니다. 체크인: 2024-03-10'),
(3, '010-2345-6789', '[코지룸] 박소연님, CR20240315002 예약이 확정되었습니다. 체크인: 2024-04-01'),
(4, '010-3456-7890', '[코지룸] 이지원님, 회원가입을 환영합니다!');

-- ============================================================
-- 인덱스 생성
-- ============================================================
CREATE INDEX idx_hotels_region ON hotels(region_id);
CREATE INDEX idx_rooms_hotel ON rooms(hotel_id);
CREATE INDEX idx_bookings_user ON bookings(user_id);
CREATE INDEX idx_bookings_room ON bookings(room_id);
CREATE INDEX idx_reviews_hotel ON reviews(hotel_id);
CREATE INDEX idx_reviews_status ON reviews(status);
