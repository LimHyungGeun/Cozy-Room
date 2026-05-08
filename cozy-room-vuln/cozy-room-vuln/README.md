# COZY ROOM — 모의해킹 연쇄 공격 시나리오 환경

> 숙박 예약 플랫폼을 가장한 웹 취약점 교육 환경  
> **8단계 연쇄 공격 체인** (기능 간 연결로만 exploit 가능)

## 빠른 시작

```bash
# 1. Docker Compose로 실행
docker-compose up --build -d

# 2. 브라우저에서 접속
http://localhost:5000

# 3. 테스트 계정
#    관리자: admin / CozyAdmin@2024!
#    일반:   kim_minjun / CozyUser@2024!
```

## 공격 체인 개요

```
STEP 1  robots.txt 발견
  ↓
STEP 2  관리자 리뷰 검토 페이지 접근 (BAC - 부분 검증)
  ↓
STEP 3  Stored XSS 삽입 (일반 페이지 escape, 관리자 페이지 raw)
  ↓
STEP 4  관리자 세션 탈취 (HttpOnly 미설정)
  ↓
STEP 5  관리자 미디어 업로드 (SVG 허용)
  ↓
STEP 6  업로드 파일 직접 접근 (SVG 내부 JS 실행)
  ↓
STEP 7  내부 API 문서 획득
  ↓
STEP 8  권한 미검증 API로 개인정보 탈취
```

## 포함된 취약점

| 분류 | 설계 방식 | 특징 |
|------|----------|------|
| Broken Access Control | 부분적 검증 누락 | 대부분의 admin 라우트는 정상 보호, 특정 1~2개만 누락 |
| Stored XSS | 관리자 타깃 | 일반 페이지는 escape, 관리자 페이지만 raw rendering |
| File Upload | 조건부 취약 | 확장자 화이트리스트 적용, 단 SVG 허용으로 JS 삽입 가능 |
| Security Misconfiguration | 부분 노출 | robots.txt, HttpOnly 미설정, 내부 API 문서 노출 |

## 제거된 취약점

- ~~Time-based Blind SQL Injection~~ → 모든 쿼리 파라미터 바인딩 적용
- ~~무제한 File Upload~~ → 확장자 화이트리스트 적용 (SVG만 조건부 취약)
- ~~exec() 실행 엔드포인트~~ → 완전 제거
- ~~디렉터리 리스팅~~ → 제거

## 파일 구조

```
cozy-room-vuln/
├── docker-compose.yml
├── README.md
├── VULNERABILITY_ANALYSIS.md    ← 상세 취약점 분석
├── db/
│   ├── Dockerfile
│   └── init.sql                 ← reviews.status 컬럼 추가
└── web/
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py                   ← 메인 애플리케이션
    ├── static/uploads/          ← 업로드 파일 저장
    └── templates/
        ├── base.html
        ├── index.html
        ├── search.html
        ├── hotel_detail.html    ← 리뷰 autoescaped (안전)
        ├── write_review.html
        ├── ... (기타 페이지)
        └── admin/
            ├── dashboard.html   ← 리뷰/미디어 메뉴 추가
            ├── bookings.html
            ├── users.html
            ├── reviews.html     ← [NEW] XSS 발동 지점 (|safe)
            └── media.html       ← [NEW] SVG 업로드 페이지
```

## 주의사항

이 프로젝트는 **교육/연구 목적**으로만 사용해야 합니다.  
실제 서비스나 인터넷에 노출된 환경에서 사용하지 마세요.
