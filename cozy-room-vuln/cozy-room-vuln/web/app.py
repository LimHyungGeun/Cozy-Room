# -*- coding: utf-8 -*-
"""
COZY ROOM - 숙박 예약 플랫폼
=====================================
보안 취약점 연구/교육 목적 프로젝트

공격 체인 시나리오 (8-STEP):
  STEP 1 — robots.txt → 관리자 경로 노출
  STEP 2 — /admin/reviews 접근 (Broken Access Control - 부분 검증)
  STEP 3 — Stored XSS (일반 페이지 escape, 관리자 페이지 raw rendering)
  STEP 4 — 관리자 세션 탈취 (HttpOnly 미설정)
  STEP 5 — 관리자 업로드 기능 (SVG 허용)
  STEP 6 — 업로드 파일 직접 접근 가능
  STEP 7 — 내부 API 정보 획득
  STEP 8 — 특정 admin API 권한검사 누락

[중요] 이 코드는 교육/연구 목적으로만 사용해야 합니다.
"""

import os
import re
import uuid
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, g,
                   send_from_directory, Response, make_response)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import MySQLdb

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cozy_secret_2017_yogi_eottae')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# ──────────────────────────────────────────────
# [STEP 4] HttpOnly 미설정 — 세션 쿠키가 JavaScript로 접근 가능
# 실무에서 Flask 기본값은 HttpOnly=True 이지만
# "세션 기반 프론트엔드 토큰 공유" 등의 이유로 끄는 실수가 발생
# ──────────────────────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads'))

# ──────────────────────────────────────────────
# [STEP 5] 파일 업로드 허용 확장자 — SVG 포함 (조건부 취약)
# 이미지 + SVG 허용. SVG 내부 <script> 가능 → Stored XSS 연결
# ──────────────────────────────────────────────
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ══════════════════════════════════════════════
# DB 연결
# ══════════════════════════════════════════════

def get_db():
    if 'db' not in g:
        g.db = MySQLdb.connect(
            host=os.environ.get('DB_HOST', 'localhost'),
            port=int(os.environ.get('DB_PORT', 3306)),
            db=os.environ.get('DB_NAME', 'cozyroom'),
            user=os.environ.get('DB_USER', 'cozyapp'),
            passwd=os.environ.get('DB_PASSWORD', 'App@C0zy2017!'),
            charset='utf8mb4',
            use_unicode=True
        )
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query_db(sql, args=None, one=False):
    """파라미터화 쿼리 실행 (SQLi 안전)"""
    db = get_db()
    cur = db.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(sql, args or ())
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(sql, args=None):
    """INSERT/UPDATE/DELETE 실행"""
    db = get_db()
    cur = db.cursor()
    cur.execute(sql, args or ())
    db.commit()
    last_id = cur.lastrowid
    cur.close()
    return last_id


# ══════════════════════════════════════════════
# 인증 데코레이터
# ══════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요한 서비스입니다.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('관리자 권한이 필요합니다.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════
# 헬퍼 함수
# ══════════════════════════════════════════════

def gen_booking_code():
    now = datetime.now().strftime('%Y%m%d')
    uid = str(uuid.uuid4().int)[:6]
    return f"CR{now}{uid}"

def allowed_file(filename):
    """확장자 화이트리스트 검사 (SVG 포함)"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def _save_uploaded_file(file, prefix='file'):
    """
    파일 업로드 저장.
    확장자 화이트리스트 검증 적용 — 단 SVG를 허용하므로 조건부 취약.
    SVG 내부 <script>, <foreignObject>, onload 등 JS 가능.
    """
    if not file or not file.filename:
        return None, None

    orig_name = file.filename
    safe_name = secure_filename(orig_name)
    if not safe_name:
        safe_name = f"{prefix}_{uuid.uuid4().hex}"

    if not allowed_file(safe_name):
        return None, None  # 허용되지 않은 확장자 거부

    ext = os.path.splitext(safe_name)[1].lower()
    unique_name = f"{prefix}_{uuid.uuid4().hex[:12]}{ext}"
    save_path = os.path.join(UPLOAD_FOLDER, unique_name)
    file.save(save_path)
    return unique_name, save_path


# ══════════════════════════════════════════════
# [STEP 1] robots.txt — 정보 노출
# Disallow 항목에 관리자/내부 경로를 명시하여 역으로 존재를 알려줌
# ══════════════════════════════════════════════

@app.route('/robots.txt')
def robots_txt():
    content = """User-agent: *
Disallow: /admin/
Disallow: /admin/reviews
Disallow: /admin/media
Disallow: /api/internal/
Disallow: /api/admin/

# Sitemap: https://cozyroom.kr/sitemap.xml
"""
    return Response(content, mimetype='text/plain')


# ══════════════════════════════════════════════
# 메인 페이지
# ══════════════════════════════════════════════

@app.route('/')
def index():
    hotels = query_db(
        "SELECT h.*, r.name as region_name FROM hotels h "
        "JOIN regions r ON h.region_id = r.id "
        "WHERE h.is_premium = 1 LIMIT 6"
    )
    regions = query_db("SELECT * FROM regions")
    recent_hotels = query_db(
        "SELECT h.*, r.name as region_name FROM hotels h "
        "JOIN regions r ON h.region_id = r.id "
        "ORDER BY h.created_at DESC LIMIT 4"
    )
    return render_template('index.html',
                           hotels=hotels,
                           regions=regions,
                           recent_hotels=recent_hotels)


# ══════════════════════════════════════════════
# 검색 (SQLi 제거 — 파라미터 바인딩 사용)
# ══════════════════════════════════════════════

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    region = request.args.get('region', '')
    checkin = request.args.get('checkin', '')
    checkout = request.args.get('checkout', '')
    sort = request.args.get('sort', 'name')

    hotels = []
    error_flag = False

    if keyword or region:
        try:
            # 파라미터 바인딩으로 안전한 쿼리
            sql = (
                "SELECT h.id, h.name, h.address, h.description, "
                "h.star_rating, h.thumbnail, h.amenities, h.is_premium, "
                "r.name as region_name "
                "FROM hotels h JOIN regions r ON h.region_id = r.id "
                "WHERE (h.name LIKE %s OR h.address LIKE %s) "
            )
            params = [f'%{keyword}%', f'%{keyword}%']

            if region:
                sql += "AND r.slug = %s "
                params.append(region)

            safe_sort = sort if sort in ('name', 'star_rating', 'id') else 'name'
            sql += f"ORDER BY h.{safe_sort}"

            hotels = query_db(sql, tuple(params))

        except Exception:
            error_flag = True
            hotels = []

    regions = query_db("SELECT * FROM regions")
    return render_template('search.html',
                           hotels=hotels,
                           keyword=keyword,
                           region=region,
                           regions=regions,
                           checkin=checkin,
                           checkout=checkout,
                           error_flag=error_flag)


# ══════════════════════════════════════════════
# 호텔 상세 페이지
# ══════════════════════════════════════════════

@app.route('/hotel/<int:hotel_id>')
def hotel_detail(hotel_id):
    hotel = query_db(
        "SELECT h.*, r.name as region_name FROM hotels h "
        "JOIN regions r ON h.region_id = r.id WHERE h.id = %s",
        (hotel_id,), one=True
    )
    if not hotel:
        flash('존재하지 않는 숙소입니다.', 'danger')
        return redirect(url_for('index'))

    rooms = query_db(
        "SELECT * FROM rooms WHERE hotel_id = %s AND is_available = 1",
        (hotel_id,)
    )
    # [STEP 3 방어측] 일반 페이지에서는 Jinja2 autoescaping 적용
    # 리뷰 내용이 {{ review.content }} 로 렌더링됨 → HTML escape 처리
    reviews = query_db(
        "SELECT rv.*, u.name as user_name FROM reviews rv "
        "JOIN users u ON rv.user_id = u.id "
        "WHERE rv.hotel_id = %s AND rv.status = 'approved' "
        "ORDER BY rv.created_at DESC LIMIT 10",
        (hotel_id,)
    )
    avg_rating = query_db(
        "SELECT AVG(rating) as avg_r, COUNT(*) as cnt FROM reviews "
        "WHERE hotel_id = %s AND status = 'approved'",
        (hotel_id,), one=True
    )
    return render_template('hotel_detail.html',
                           hotel=hotel, rooms=rooms,
                           reviews=reviews, avg_rating=avg_rating)


# ══════════════════════════════════════════════
# 객실 예약
# ══════════════════════════════════════════════

@app.route('/booking/<int:room_id>', methods=['GET', 'POST'])
@login_required
def booking(room_id):
    room = query_db(
        "SELECT r.*, h.name as hotel_name, h.id as hotel_id, "
        "h.check_in, h.check_out, reg.name as region_name "
        "FROM rooms r JOIN hotels h ON r.hotel_id = h.id "
        "JOIN regions reg ON h.region_id = reg.id "
        "WHERE r.id = %s",
        (room_id,), one=True
    )
    if not room:
        flash('존재하지 않는 객실입니다.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        guest_name = request.form.get('guest_name', '').strip()
        guest_phone = request.form.get('guest_phone', '').strip()
        checkin = request.form.get('checkin', '')
        checkout = request.form.get('checkout', '')
        special_req = request.form.get('special_req', '')
        payment = request.form.get('payment_method', '신용카드')
        coupon_code = request.form.get('coupon_code', '').strip()

        if not all([guest_name, guest_phone, checkin, checkout]):
            flash('필수 정보를 모두 입력해주세요.', 'danger')
            return render_template('booking.html', room=room)

        try:
            ci = datetime.strptime(checkin, '%Y-%m-%d')
            co = datetime.strptime(checkout, '%Y-%m-%d')
            nights = (co - ci).days
            if nights < 1:
                flash('체크인/체크아웃 날짜를 확인해주세요.', 'danger')
                return render_template('booking.html', room=room)
        except ValueError:
            flash('날짜 형식이 올바르지 않습니다.', 'danger')
            return render_template('booking.html', room=room)

        total_price = room['price'] * nights

        if coupon_code:
            coupon = query_db(
                "SELECT * FROM coupons WHERE code = %s AND is_used = 0 "
                "AND (valid_until IS NULL OR valid_until >= CURDATE())",
                (coupon_code,), one=True
            )
            if coupon:
                discount = int(total_price * coupon['discount_pct'] / 100)
                total_price -= discount
                flash(f"쿠폰 적용: {coupon['discount_pct']}% 할인 (-{discount:,}원)", 'success')
            else:
                flash('유효하지 않은 쿠폰입니다.', 'warning')

        booking_code = gen_booking_code()
        execute_db(
            "INSERT INTO bookings (booking_code, user_id, room_id, guest_name, "
            "guest_phone, check_in_date, check_out_date, nights, total_price, "
            "special_req, status, payment_method) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'대기',%s)",
            (booking_code, session['user_id'], room_id, guest_name,
             guest_phone, checkin, checkout, nights, total_price,
             special_req, payment)
        )

        execute_db(
            "INSERT INTO sms_logs (user_id, phone, message) VALUES (%s,%s,%s)",
            (session['user_id'], guest_phone,
             f"[코지룸] {guest_name}님, {booking_code} 예약이 접수되었습니다. "
             f"체크인: {checkin}")
        )

        flash(f'예약이 완료되었습니다! 예약번호: {booking_code}', 'success')
        return redirect(url_for('booking_confirm', booking_code=booking_code))

    return render_template('booking.html', room=room)


@app.route('/booking/confirm/<booking_code>')
@login_required
def booking_confirm(booking_code):
    booking = query_db(
        "SELECT b.*, r.room_name, r.price, h.name as hotel_name, "
        "h.address, reg.name as region_name "
        "FROM bookings b JOIN rooms r ON b.room_id = r.id "
        "JOIN hotels h ON r.hotel_id = h.id "
        "JOIN regions reg ON h.region_id = reg.id "
        "WHERE b.booking_code = %s AND b.user_id = %s",
        (booking_code, session['user_id']), one=True
    )
    if not booking:
        return redirect(url_for('index'))
    return render_template('booking_confirm.html', booking=booking)


# ══════════════════════════════════════════════
# 예약 조회 (SQLi 제거 — 파라미터 바인딩)
# ══════════════════════════════════════════════

@app.route('/booking/check', methods=['GET', 'POST'])
def booking_check():
    result = None
    if request.method == 'POST':
        booking_code = request.form.get('booking_code', '').strip()
        guest_phone = request.form.get('guest_phone', '').strip()

        result = query_db(
            "SELECT b.booking_code, b.guest_name, b.check_in_date, "
            "b.check_out_date, b.total_price, b.status, "
            "h.name as hotel_name, r.room_name "
            "FROM bookings b JOIN rooms r ON b.room_id = r.id "
            "JOIN hotels h ON r.hotel_id = h.id "
            "WHERE b.booking_code = %s AND b.guest_phone = %s",
            (booking_code, guest_phone), one=True
        )

    return render_template('booking_check.html', result=result)


# ══════════════════════════════════════════════
# 내 예약 내역
# ══════════════════════════════════════════════

@app.route('/my/bookings')
@login_required
def my_bookings():
    bookings = query_db(
        "SELECT b.*, r.room_name, r.price, h.name as hotel_name, "
        "h.thumbnail, reg.name as region_name "
        "FROM bookings b JOIN rooms r ON b.room_id = r.id "
        "JOIN hotels h ON r.hotel_id = h.id "
        "JOIN regions reg ON h.region_id = reg.id "
        "WHERE b.user_id = %s ORDER BY b.created_at DESC",
        (session['user_id'],)
    )
    return render_template('my_bookings.html', bookings=bookings)


@app.route('/my/booking/cancel/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    booking = query_db(
        "SELECT * FROM bookings WHERE id = %s AND user_id = %s",
        (booking_id, session['user_id']), one=True
    )
    if booking and booking['status'] in ('대기', '확정'):
        execute_db(
            "UPDATE bookings SET status = '취소' WHERE id = %s",
            (booking_id,)
        )
        flash('예약이 취소되었습니다.', 'info')
    return redirect(url_for('my_bookings'))


# ══════════════════════════════════════════════
# [STEP 3] 리뷰 작성 — Stored XSS 삽입 포인트
# content 필드에 HTML/JS 삽입 가능 (DB에 raw 저장)
# - 일반 hotel_detail 페이지: {{ review.content }} → autoescaped (안전)
# - 관리자 리뷰 검토 페이지: {{ review.content|safe }} → raw rendering (취약)
# ══════════════════════════════════════════════

@app.route('/review/write/<int:booking_id>', methods=['GET', 'POST'])
@login_required
def write_review(booking_id):
    booking = query_db(
        "SELECT b.*, h.id as hotel_id, h.name as hotel_name, r.room_name "
        "FROM bookings b JOIN rooms r ON b.room_id = r.id "
        "JOIN hotels h ON r.hotel_id = h.id "
        "WHERE b.id = %s AND b.user_id = %s",
        (booking_id, session['user_id']), one=True
    )
    if not booking:
        flash('리뷰를 작성할 수 없는 예약입니다.', 'danger')
        return redirect(url_for('my_bookings'))

    existing = query_db(
        "SELECT id FROM reviews WHERE booking_id = %s", (booking_id,), one=True
    )
    if existing:
        flash('이미 리뷰를 작성하셨습니다.', 'warning')
        return redirect(url_for('my_bookings'))

    if request.method == 'POST':
        rating = request.form.get('rating', 5)
        title = request.form.get('title', '')
        content = request.form.get('content', '')

        # 파일 업로드 (이미지/SVG 허용)
        file = request.files.get('review_image')
        fname, fpath = _save_uploaded_file(file, prefix='review')
        if fname:
            try:
                execute_db(
                    "INSERT INTO uploads (user_id, filename, orig_name, file_path) "
                    "VALUES (%s,%s,%s,%s)",
                    (session['user_id'], fname, file.filename, fpath)
                )
            except Exception:
                pass

        # 리뷰를 DB에 저장 — content는 raw 상태 그대로 (XSS 페이로드 포함 가능)
        # status는 'pending'으로 관리자 검토 대기
        try:
            execute_db(
                "INSERT INTO reviews (booking_id, user_id, hotel_id, rating, "
                "title, content, image_path, status) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,'pending')",
                (booking_id, session['user_id'], booking['hotel_id'],
                 rating, title, content, fname)
            )
        except Exception:
            pass
        flash('리뷰가 등록되었습니다. 관리자 검토 후 게시됩니다.', 'success')
        return redirect(url_for('my_bookings'))

    return render_template('write_review.html', booking=booking)


# ══════════════════════════════════════════════
# 회원가입
# ══════════════════════════════════════════════

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        email = request.form.get('email', '').strip()
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        birth_date = request.form.get('birth_date', '')
        address = request.form.get('address', '').strip()

        errors = []
        if not all([username, password, email, name, phone]):
            errors.append('필수 항목을 모두 입력해주세요.')
        if password != password2:
            errors.append('비밀번호가 일치하지 않습니다.')
        if len(password) < 8:
            errors.append('비밀번호는 8자 이상이어야 합니다.')
        if not re.match(r'^[a-zA-Z0-9_]{4,20}$', username):
            errors.append('아이디는 4~20자의 영문, 숫자, 언더스코어만 사용 가능합니다.')

        dup_user = query_db("SELECT id FROM users WHERE username = %s",
                            (username,), one=True)
        dup_email = query_db("SELECT id FROM users WHERE email = %s",
                             (email,), one=True)
        if dup_user:
            errors.append('이미 사용 중인 아이디입니다.')
        if dup_email:
            errors.append('이미 사용 중인 이메일입니다.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html')

        hashed_pw = generate_password_hash(password)
        new_user_id = execute_db(
            "INSERT INTO users (username, password, email, name, phone, "
            "birth_date, address) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (username, hashed_pw, email, name, phone, birth_date or None, address)
        )

        try:
            execute_db(
                "INSERT INTO sms_logs (user_id, phone, message) VALUES (%s,%s,%s)",
                (new_user_id, phone,
                 f"[코지룸] {name}님, 회원가입을 환영합니다! "
                 f"첫 예약 시 WELCOME10 쿠폰을 사용해보세요.")
            )
        except Exception:
            pass

        flash('회원가입이 완료되었습니다. 로그인해주세요.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# ══════════════════════════════════════════════
# 로그인 / 로그아웃 (SQLi 제거 — 파라미터 바인딩)
# ══════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = query_db(
            "SELECT id, username, name, password, is_admin, phone, email "
            "FROM users WHERE username = %s",
            (username,), one=True
        )

        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['name'] = user['name']
            session['is_admin'] = bool(user['is_admin'])
            try:
                execute_db(
                    "UPDATE users SET last_login = NOW() WHERE id = %s",
                    (user['id'],)
                )
            except Exception:
                pass
            flash(f"{user['name']}님, 환영합니다!", 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('index'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃 되었습니다.', 'info')
    return redirect(url_for('index'))


# ══════════════════════════════════════════════
# 마이페이지 - 프로필
# ══════════════════════════════════════════════

@app.route('/my/profile', methods=['GET', 'POST'])
@login_required
def my_profile():
    user = query_db(
        "SELECT * FROM users WHERE id = %s", (session['user_id'],), one=True
    )

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()

        profile_img = user['profile_img']
        if 'profile_img' in request.files:
            file = request.files['profile_img']
            fname, fpath = _save_uploaded_file(file, prefix='profile')
            if fname:
                try:
                    execute_db(
                        "INSERT INTO uploads (user_id, filename, orig_name, "
                        "file_path) VALUES (%s,%s,%s,%s)",
                        (session['user_id'], fname, file.filename, fpath)
                    )
                except Exception:
                    pass
                profile_img = fname

        execute_db(
            "UPDATE users SET name=%s, phone=%s, address=%s, profile_img=%s "
            "WHERE id=%s",
            (name, phone, address, profile_img, session['user_id'])
        )
        session['name'] = name
        flash('프로필이 업데이트되었습니다.', 'success')
        return redirect(url_for('my_profile'))

    return render_template('my_profile.html', user=user)


@app.route('/my/password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        user = query_db("SELECT * FROM users WHERE id = %s",
                        (session['user_id'],), one=True)

        if not check_password_hash(user['password'], current_pw):
            flash('현재 비밀번호가 올바르지 않습니다.', 'danger')
        elif new_pw != confirm_pw:
            flash('새 비밀번호가 일치하지 않습니다.', 'danger')
        elif len(new_pw) < 8:
            flash('비밀번호는 8자 이상이어야 합니다.', 'danger')
        else:
            execute_db(
                "UPDATE users SET password = %s WHERE id = %s",
                (generate_password_hash(new_pw), session['user_id'])
            )
            flash('비밀번호가 변경되었습니다.', 'success')
            return redirect(url_for('my_profile'))

    return render_template('change_password.html')


# ══════════════════════════════════════════════
# 쿠폰 등록
# ══════════════════════════════════════════════

@app.route('/my/coupon', methods=['GET', 'POST'])
@login_required
def my_coupon():
    if request.method == 'POST':
        code = request.form.get('coupon_code', '').strip().upper()
        coupon = query_db(
            "SELECT * FROM coupons WHERE code = %s AND is_used = 0 "
            "AND (valid_until IS NULL OR valid_until >= CURDATE())",
            (code,), one=True
        )
        if coupon:
            execute_db(
                "UPDATE coupons SET is_used = 1, used_by = %s WHERE id = %s",
                (session['user_id'], coupon['id'])
            )
            flash(f"쿠폰이 등록되었습니다! ({coupon['discount_pct']}% 할인)", 'success')
        else:
            flash('유효하지 않거나 이미 사용된 쿠폰입니다.', 'danger')

    coupons = query_db(
        "SELECT * FROM coupons WHERE used_by = %s", (session['user_id'],)
    )
    return render_template('my_coupon.html', coupons=coupons)


# ══════════════════════════════════════════════
# 관리자 페이지 — 정상 보호 엔드포인트들
# ══════════════════════════════════════════════

@app.route('/admin')
@admin_required
def admin_dashboard():
    stats = {
        'total_users': query_db(
            "SELECT COUNT(*) as c FROM users WHERE is_admin=0", one=True)['c'],
        'total_bookings': query_db(
            "SELECT COUNT(*) as c FROM bookings", one=True)['c'],
        'total_revenue': query_db(
            "SELECT COALESCE(SUM(total_price),0) as s FROM bookings "
            "WHERE status='완료'", one=True)['s'],
        'pending': query_db(
            "SELECT COUNT(*) as c FROM bookings WHERE status='대기'",
            one=True)['c'],
        'pending_reviews': query_db(
            "SELECT COUNT(*) as c FROM reviews WHERE status='pending'",
            one=True)['c'],
    }
    recent_bookings = query_db(
        "SELECT b.*, u.name as user_name, h.name as hotel_name, r.room_name "
        "FROM bookings b JOIN users u ON b.user_id = u.id "
        "JOIN rooms r ON b.room_id = r.id "
        "JOIN hotels h ON r.hotel_id = h.id "
        "ORDER BY b.created_at DESC LIMIT 10"
    )
    recent_users = query_db(
        "SELECT * FROM users WHERE is_admin = 0 "
        "ORDER BY created_at DESC LIMIT 10"
    )
    return render_template('admin/dashboard.html',
                           stats=stats,
                           recent_bookings=recent_bookings,
                           recent_users=recent_users)


@app.route('/admin/bookings')
@admin_required
def admin_bookings():
    status_filter = request.args.get('status', '')
    if status_filter:
        bookings = query_db(
            "SELECT b.*, u.name as user_name, h.name as hotel_name, "
            "r.room_name FROM bookings b JOIN users u ON b.user_id = u.id "
            "JOIN rooms r ON b.room_id = r.id "
            "JOIN hotels h ON r.hotel_id = h.id "
            "WHERE b.status = %s ORDER BY b.created_at DESC",
            (status_filter,)
        )
    else:
        bookings = query_db(
            "SELECT b.*, u.name as user_name, h.name as hotel_name, "
            "r.room_name FROM bookings b JOIN users u ON b.user_id = u.id "
            "JOIN rooms r ON b.room_id = r.id "
            "JOIN hotels h ON r.hotel_id = h.id "
            "ORDER BY b.created_at DESC"
        )
    return render_template('admin/bookings.html',
                           bookings=bookings, status_filter=status_filter)


@app.route('/admin/booking/update/<int:booking_id>', methods=['POST'])
@admin_required
def admin_update_booking(booking_id):
    status = request.form.get('status')
    if status in ('대기', '확정', '취소', '완료'):
        execute_db(
            "UPDATE bookings SET status = %s WHERE id = %s",
            (status, booking_id)
        )
        flash('예약 상태가 업데이트되었습니다.', 'success')
    return redirect(url_for('admin_bookings'))


@app.route('/admin/users')
@admin_required
def admin_users():
    users = query_db(
        "SELECT u.*, COUNT(b.id) as booking_count "
        "FROM users u LEFT JOIN bookings b ON u.id = b.user_id "
        "WHERE u.is_admin = 0 GROUP BY u.id ORDER BY u.created_at DESC"
    )
    return render_template('admin/users.html', users=users)


# ══════════════════════════════════════════════════════════════
# [STEP 2 + STEP 3] 관리자 리뷰 검토 페이지
# ── Broken Access Control (부분 검증) ──
#
# 의도: 관리자 전용이어야 하는 리뷰 검토 페이지
# 실수: @admin_required 대신 @login_required 만 적용
#       (개발자가 "로그인 확인이면 충분하다"고 착각한 시나리오)
#
# 이 페이지에서 리뷰 content를 |safe 필터로 렌더링
# → 관리자가 "서식 미리보기"를 위해 raw HTML 을 봐야 하기 때문이라는 논리
# → Stored XSS 가 이 페이지에서 발동
# ══════════════════════════════════════════════════════════════

@app.route('/admin/reviews')
@login_required  # ← [취약점] @admin_required 가 아닌 @login_required
def admin_reviews():
    status_filter = request.args.get('status', 'pending')
    if status_filter == 'all':
        reviews = query_db(
            "SELECT rv.*, u.name as user_name, u.username, "
            "h.name as hotel_name "
            "FROM reviews rv JOIN users u ON rv.user_id = u.id "
            "JOIN hotels h ON rv.hotel_id = h.id "
            "ORDER BY rv.created_at DESC"
        )
    else:
        reviews = query_db(
            "SELECT rv.*, u.name as user_name, u.username, "
            "h.name as hotel_name "
            "FROM reviews rv JOIN users u ON rv.user_id = u.id "
            "JOIN hotels h ON rv.hotel_id = h.id "
            "WHERE rv.status = %s ORDER BY rv.created_at DESC",
            (status_filter,)
        )
    return render_template('admin/reviews.html',
                           reviews=reviews, status_filter=status_filter)


@app.route('/admin/review/update/<int:review_id>', methods=['POST'])
@admin_required
def admin_update_review(review_id):
    action = request.form.get('action')
    if action == 'approve':
        execute_db("UPDATE reviews SET status = 'approved' WHERE id = %s",
                   (review_id,))
        flash('리뷰가 승인되었습니다.', 'success')
    elif action == 'reject':
        execute_db("UPDATE reviews SET status = 'rejected' WHERE id = %s",
                   (review_id,))
        flash('리뷰가 거부되었습니다.', 'info')
    return redirect(url_for('admin_reviews'))


# ══════════════════════════════════════════════════════════════
# [STEP 5] 관리자 미디어 업로드 페이지
# 호텔 썸네일/아이콘 등을 관리하기 위한 업로드 기능
# SVG 파일 업로드 허용 → SVG 내부 JS 실행 가능
# ══════════════════════════════════════════════════════════════

@app.route('/admin/media', methods=['GET', 'POST'])
@admin_required
def admin_media():
    uploaded_info = None
    if request.method == 'POST':
        file = request.files.get('media_file')
        fname, fpath = _save_uploaded_file(file, prefix='media')
        if fname:
            try:
                execute_db(
                    "INSERT INTO uploads (user_id, filename, orig_name, "
                    "file_path) VALUES (%s,%s,%s,%s)",
                    (session['user_id'], fname, file.filename, fpath)
                )
            except Exception:
                pass
            uploaded_info = {
                'filename': fname,
                'orig_name': file.filename,
                'web_path': f'/static/uploads/{fname}',
            }
        else:
            flash('허용되지 않은 파일 형식입니다. (png, jpg, jpeg, gif, svg만 허용)',
                  'danger')

    # 기존 업로드 파일 목록
    uploads = query_db(
        "SELECT * FROM uploads ORDER BY upload_at DESC LIMIT 50"
    )
    return render_template('admin/media.html',
                           uploaded_info=uploaded_info, uploads=uploads)


# ══════════════════════════════════════════════════════════════
# [STEP 6] 업로드 파일 직접 접근
# Flask /static/uploads/ 는 기본 서빙됨
# SVG 파일은 image/svg+xml Content-Type으로 서빙되어
# 브라우저가 내부 <script>를 실행함
# ══════════════════════════════════════════════════════════════

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    """업로드 파일 직접 서빙"""
    return send_from_directory(UPLOAD_FOLDER, filename)


# ══════════════════════════════════════════════════════════════
# [STEP 7] 내부 API — 관리용 엔드포인트 정보
# robots.txt 에서 /api/internal/ 존재를 알 수 있음
# 여기서 내부 API 목록(엔드포인트 문서)을 노출
# ══════════════════════════════════════════════════════════════

@app.route('/api/internal/docs')
@login_required  # 로그인만 검사 (관리자 검사 누락)
def api_internal_docs():
    """내부 API 문서 — 개발자 참조용 (실수로 노출)"""
    docs = {
        'service': 'COZY ROOM Internal API',
        'version': '2.1.0',
        'endpoints': [
            {
                'method': 'GET',
                'path': '/api/admin/users/export',
                'description': '전체 사용자 목록 CSV 내보내기',
                'auth': 'admin session required',
                'params': {'format': 'json|csv'}
            },
            {
                'method': 'GET',
                'path': '/api/admin/bookings/export',
                'description': '예약 내역 전체 조회',
                'auth': 'admin session required',
                'params': {'status': 'all|pending|confirmed|cancelled'}
            },
            {
                'method': 'GET',
                'path': '/api/admin/stats',
                'description': '서비스 통계 요약',
                'auth': 'admin session required'
            },
            {
                'method': 'POST',
                'path': '/api/admin/user/role',
                'description': '사용자 권한 변경',
                'auth': 'admin session required',
                'params': {'user_id': 'int', 'is_admin': '0|1'}
            },
        ],
        'note': 'All endpoints require valid admin session cookie.'
    }
    return jsonify(docs)


# ══════════════════════════════════════════════════════════════
# [STEP 8] Broken Access Control — 특정 API 권한검사 누락
#
# /api/admin/users/export — 사용자 데이터 전체 내보내기
# 이 엔드포인트에는 @admin_required 가 빠져있음
# (개발자가 여러 API를 만들면서 이것만 데코레이터 적용을 깜빡한 시나리오)
#
# 나머지 admin API는 정상적으로 @admin_required 적용
# ══════════════════════════════════════════════════════════════

@app.route('/api/admin/users/export')
@login_required  # ← [취약점] @admin_required 가 아닌 @login_required
def api_admin_users_export():
    """전체 사용자 목록 — 개인정보 포함"""
    fmt = request.args.get('format', 'json')
    users = query_db(
        "SELECT id, username, email, phone, name, birth_date, address, "
        "created_at, last_login FROM users WHERE is_admin = 0"
    )

    print(type(users[0]))
    print(users[0])

    if fmt == 'csv':
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['id', 'username', 'email', 'phone', 'name',
                         'birth_date', 'address', 'created_at', 'last_login'])
        for u in users:
            writer.writerow([
                u['id'], u['username'], u['email'], u['phone'],
                u['name'], str(u.get('birth_date', '')),
                u['address'], str(u.get('created_at', '')),
                str(u.get('last_login', ''))
            ])
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=users_export.csv'}
        )

    return jsonify({
        'total': len(users),
        'users': [dict(u) for u in users]
    })


# 정상 보호된 admin API들 (비교용)
@app.route('/api/admin/bookings/export')
@admin_required  # ← 정상
def api_admin_bookings_export():
    bookings = query_db(
        "SELECT b.*, u.name as user_name, h.name as hotel_name "
        "FROM bookings b JOIN users u ON b.user_id = u.id "
        "JOIN rooms r ON b.room_id = r.id "
        "JOIN hotels h ON r.hotel_id = h.id "
        "ORDER BY b.created_at DESC"
    )
    return jsonify({'bookings': [dict(b) for b in bookings]}, default=str)


@app.route('/api/admin/stats')
@admin_required  # ← 정상
def api_admin_stats():
    stats = {
        'users': query_db(
            "SELECT COUNT(*) as c FROM users WHERE is_admin=0",
            one=True)['c'],
        'bookings': query_db(
            "SELECT COUNT(*) as c FROM bookings", one=True)['c'],
        'revenue': query_db(
            "SELECT COALESCE(SUM(total_price),0) as s FROM bookings "
            "WHERE status='완료'", one=True)['s'],
    }
    return jsonify(stats, default=str)


@app.route('/api/admin/user/role', methods=['POST'])
@admin_required  # ← 정상
def api_admin_user_role():
    user_id = request.json.get('user_id') if request.is_json else None
    is_admin = request.json.get('is_admin') if request.is_json else None
    if user_id is None or is_admin is None:
        return jsonify({'error': 'user_id and is_admin required'}), 400
    execute_db(
        "UPDATE users SET is_admin = %s WHERE id = %s",
        (int(is_admin), int(user_id))
    )
    return jsonify({'success': True, 'user_id': user_id, 'is_admin': is_admin})


# ══════════════════════════════════════════════
# 공개 API
# ══════════════════════════════════════════════

@app.route('/api/rooms/available')
def api_rooms_available():
    hotel_id = request.args.get('hotel_id')
    if not hotel_id:
        return jsonify({'error': 'hotel_id required'}), 400
    rooms = query_db(
        "SELECT * FROM rooms WHERE hotel_id = %s AND is_available = 1",
        (hotel_id,)
    )
    return jsonify({'rooms': [dict(r) for r in rooms]})


@app.route('/api/hotels/region/<slug>')
def api_hotels_by_region(slug):
    hotels = query_db(
        "SELECT h.id, h.name, h.address, h.star_rating, h.thumbnail "
        "FROM hotels h JOIN regions r ON h.region_id = r.id "
        "WHERE r.slug = %s", (slug,)
    )
    return jsonify({'hotels': [dict(h) for h in hotels]})



# ══════════════════════════════════════════════
# 정적 페이지
# ══════════════════════════════════════════════

@app.route('/notice')
def notice():
    return render_template('notice.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/about')
def about():
    return render_template('about.html')


# ══════════════════════════════════════════════
# 에러 핸들러
# ══════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404,
                           msg='페이지를 찾을 수 없습니다.'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', code=500,
                           msg='서버 오류가 발생했습니다.'), 500


# ══════════════════════════════════════════════
# 템플릿 필터
# ══════════════════════════════════════════════

@app.template_filter('format_price')
def format_price(value):
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return value

@app.template_filter('format_time')
def format_time(value):
    if value is None:
        return ''
    from datetime import timedelta, time as dt_time
    if isinstance(value, timedelta):
        total = int(value.total_seconds())
        return f"{total // 3600:02d}:{(total % 3600) // 60:02d}"
    if isinstance(value, dt_time):
        return value.strftime('%H:%M')
    return str(value)

@app.template_filter('format_date')
def format_date(value):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            return value
    if hasattr(value, 'strftime'):
        return value.strftime('%Y년 %m월 %d일')
    return value

@app.template_filter('star_range')
def star_range(value):
    return range(int(value or 0))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
