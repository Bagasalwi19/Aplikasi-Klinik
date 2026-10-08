from flask import Flask, request, jsonify, render_template_string, session, send_file
import sqlite3
from pathlib import Path
import base64
import io
import re
import unicodedata
import os
import json
import urllib.parse
import urllib.request
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from calendar import monthrange

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'klinik.db'
app.secret_key = os.environ.get('ETH_SECRET_KEY') or os.urandom(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')

DAFTAR_IZIN = {
    'menu_kasir':'Kasir Transaksi', 'aksi_transaksi':'Membuat/mengubah transaksi',
    'menu_billing':'Billing & Nota', 'aksi_pembayaran':'Menerima pembayaran/pelunasan',
    'menu_kurang_bayar':'Kurang Bayar', 'menu_stok':'Stok & Treatment',
    'aksi_stok':'Tambah/edit/nonaktifkan stok & treatment', 'menu_pasien':'Database RM',
    'aksi_pasien':'Tambah/edit/nonaktifkan pasien', 'menu_laporan':'Laporan Bulanan',
    'menu_pengeluaran':'Pengeluaran Operasional', 'aksi_pengeluaran':'Tambah/hapus pengeluaran',
    'menu_aset':'Aset', 'aksi_aset':'Tambah/edit/arsipkan aset',
    'menu_karyawan':'Data Karyawan & history absensi', 'aksi_karyawan':'Tambah/edit/nonaktifkan karyawan dan akun',
    'menu_absensi':'Absensi Online', 'absensi_karyawan_lain':'Memilih dan mengabsenkan karyawan lain',
    'pengaturan_akses':'Pengaturan Jabatan & Hak Akses'
}

ENDPOINT_IZIN = {
    'checkout':'aksi_transaksi','edit_item':'aksi_stok','tambah_item':'aksi_stok','hapus_item':'aksi_stok','ubah_status_item':'aksi_stok',
    'tambah_pasien':'aksi_pasien','edit_pasien':'aksi_pasien','ubah_status_pasien':'aksi_pasien',
    'tambah_pembayaran':'aksi_pembayaran','lunasi_billing':'aksi_pembayaran','hapus_billing':'aksi_pembayaran',
    'laporan_bulanan':'menu_laporan','hapus_pengeluaran':'aksi_pengeluaran','ubah_aset':'aksi_aset','status_aset':'aksi_aset','status_karyawan':'aksi_karyawan',
    'history_absensi_karyawan':'menu_karyawan','bukti_foto_absensi':'menu_karyawan','edit_karyawan_admin':'aksi_karyawan','reset_password_karyawan':'aksi_karyawan'
}

@app.route('/')
def index():
    with open(BASE_DIR / 'index.html', 'r', encoding='utf-8') as f:
        return render_template_string(f.read())

@app.after_request
def nonaktifkan_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def sekarang():
    """Waktu operasional klinik (WIB), konsisten untuk web dan ponsel."""
    return datetime.utcnow() + timedelta(hours=7)

def pengguna_saat_ini():
    akun_id=session.get('akun_id')
    if not akun_id: return None
    conn=get_db();akun=conn.execute("SELECT * FROM akun WHERE id=? AND aktif=1",(akun_id,)).fetchone();conn.close()
    return dict(akun) if akun else None

def izin_pengguna(akun):
    if not akun: return set()
    if akun.get('is_owner'): return set(DAFTAR_IZIN)
    conn=get_db();row=conn.execute("SELECT permissions FROM jabatan_akses WHERE jabatan=?",(akun.get('jabatan',''),)).fetchone();conn.close()
    try: izin=set(json.loads(row['permissions'])) if row else set()
    except (ValueError,TypeError): izin=set()
    izin.add('menu_absensi')
    return izin

@app.before_request
def lindungi_api():
    if not request.path.startswith('/api/') or request.endpoint in {'auth_status','auth_setup','auth_login'}: return
    akun=pengguna_saat_ini()
    if not akun: return jsonify({'status':'error','pesan':'Sesi login berakhir. Silakan login kembali.','perlu_login':True}),401
    perlu=ENDPOINT_IZIN.get(request.endpoint)
    khusus={
        ('kelola_pengeluaran','POST'):'aksi_pengeluaran',('kelola_aset','POST'):'aksi_aset',
        ('kelola_karyawan','GET'):'menu_karyawan',('kelola_karyawan','POST'):'aksi_karyawan',('karyawan_ringkas','GET'):'menu_absensi',('kelola_akses','GET'):'pengaturan_akses',
        ('kelola_akses','POST'):'pengaturan_akses',('kelola_akun','POST'):'aksi_karyawan',
        ('kelola_absensi','POST'):'menu_absensi'
    }
    perlu=khusus.get((request.endpoint,request.method),perlu)
    if perlu and perlu not in izin_pengguna(akun):
        return jsonify({'status':'error','pesan':'Akun Anda tidak memiliki izin untuk tindakan ini.'}),403

@app.route('/api/auth/status')
def auth_status():
    conn=get_db();sudah_ada=bool(conn.execute("SELECT 1 FROM akun WHERE is_owner=1").fetchone());conn.close()
    akun=pengguna_saat_ini()
    return jsonify({'setup_required':not sudah_ada,'logged_in':bool(akun),'user':akun and {'id':akun['id'],'nama':akun['nama'],'username':akun['username'],'jabatan':akun['jabatan'],'is_owner':bool(akun['is_owner'])},'permissions':sorted(izin_pengguna(akun))})

@app.route('/api/auth/setup',methods=['POST'])
def auth_setup():
    data=request.get_json(silent=True) or {};conn=get_db()
    try:
        if conn.execute("SELECT 1 FROM akun WHERE is_owner=1").fetchone(): raise ValueError('Akun Owner sudah tersedia.')
        username=str(data.get('username','')).strip();password=str(data.get('password',''));nama=str(data.get('nama','Owner')).strip() or 'Owner'
        if len(username)<4 or len(password)<8: raise ValueError('Username minimal 4 karakter dan password minimal 8 karakter.')
        cur=conn.execute("INSERT INTO akun(username,password_hash,nama,jabatan,is_owner) VALUES(?,?,?,?,1)",(username,generate_password_hash(password),nama,'Owner'));conn.commit();session['akun_id']=cur.lastrowid
        return jsonify({'status':'sukses','pesan':'Akun Owner berhasil dibuat.'})
    except (ValueError,sqlite3.IntegrityError) as e: return jsonify({'status':'error','pesan':str(e)}),400
    finally: conn.close()

@app.route('/api/auth/login',methods=['POST'])
def auth_login():
    data=request.get_json(silent=True) or {};conn=get_db();akun=conn.execute("SELECT * FROM akun WHERE username=? AND aktif=1",(str(data.get('username','')).strip(),)).fetchone();conn.close()
    if not akun or not check_password_hash(akun['password_hash'],str(data.get('password',''))): return jsonify({'status':'error','pesan':'Username atau password salah.'}),401
    session.clear();session['akun_id']=akun['id'];return jsonify({'status':'sukses','pesan':f"Selamat datang, {akun['nama']}."})

@app.route('/api/auth/logout',methods=['POST'])
def auth_logout(): session.clear();return jsonify({'status':'sukses'})

@app.route('/api/hak-akses',methods=['GET','POST'])
def kelola_akses():
    conn=get_db()
    if request.method=='GET':
        rows={r['jabatan']:json.loads(r['permissions'] or '[]') for r in conn.execute("SELECT * FROM jabatan_akses").fetchall()}
        jabatan=sorted({r['jabatan'] for r in conn.execute("SELECT jabatan FROM karyawan WHERE jabatan!=''").fetchall()})
        conn.close();return jsonify({'daftar_izin':DAFTAR_IZIN,'jabatan':jabatan,'akses':rows})
    data=request.get_json(silent=True) or {};jabatan=str(data.get('jabatan','')).strip();permissions=[p for p in data.get('permissions',[]) if p in DAFTAR_IZIN]
    if not jabatan or jabatan.lower()=='owner': conn.close();return jsonify({'status':'error','pesan':'Jabatan Owner tidak dapat diubah.'}),400
    conn.execute("INSERT INTO jabatan_akses(jabatan,permissions) VALUES(?,?) ON CONFLICT(jabatan) DO UPDATE SET permissions=excluded.permissions",(jabatan,json.dumps(permissions)));conn.commit();conn.close()
    return jsonify({'status':'sukses','pesan':f'Hak akses jabatan {jabatan} berhasil disimpan.'})

def buat_kode_otomatis(conn, tabel, kolom, prefix):
    rows = conn.execute(
        f"SELECT {kolom} FROM {tabel} WHERE {kolom} LIKE ?",
        (f"{prefix}-%",)
    ).fetchall()
    nomor = []
    for row in rows:
        try:
            nomor.append(int(row[kolom].split('-')[-1]))
        except (ValueError, AttributeError):
            continue
    return f"{prefix}-{max(nomor, default=0) + 1:03d}"

def normalisasi_nama(nama):
    teks = unicodedata.normalize('NFKD', nama).encode('ascii', 'ignore').decode()
    return re.sub(r'[^a-z0-9]+', ' ', teks.lower()).strip()

def username_dari_panggilan(conn, panggilan, abaikan_akun_id=None):
    dasar=re.sub(r'[^a-z0-9]', '', normalisasi_nama(panggilan)) or 'karyawan'
    kandidat=dasar;nomor=2
    while conn.execute("SELECT 1 FROM akun WHERE username=? AND (? IS NULL OR id!=?)",(kandidat,abaikan_akun_id,abaikan_akun_id)).fetchone():
        kandidat=f'{dasar}{nomor}';nomor+=1
    return kandidat

def prefix_kode_nama(nama, tipe):
    teks = normalisasi_nama(nama)
    tokens = teks.split()
    kategori = [
        (('skin', 'booster'), 'SKB'), (('sunscreen',), 'SUN'),
        (('serum',), 'SER'), (('krim',), 'KRM'), (('cream',), 'KRM'),
        (('facial',), 'FAC'), (('laser',), 'LAS'), (('toner',), 'TON'),
        (('moisturizer',), 'MOI'), (('cleanser',), 'CLE'),
        (('peeling',), 'PEL'), (('injection',), 'INJ')
    ]
    for kata_kategori, singkatan in kategori:
        if all(kata in tokens for kata in kata_kategori):
            return singkatan
    if tokens:
        huruf = re.sub(r'[^A-Z0-9]', '', tokens[0].upper())
        return (huruf[:3] or ('PRD' if tipe == 'Produk' else 'TRT')).ljust(3, 'X')
    return 'PRD' if tipe == 'Produk' else 'TRT'

def kode_nama_unik(conn, nama, tipe, abaikan_kode=None):
    prefix = prefix_kode_nama(nama, tipe)
    rows = conn.execute("SELECT kode FROM barang WHERE kode LIKE ?", (f'{prefix}%',)).fetchall()
    nomor = []
    for row in rows:
        if abaikan_kode and row['kode'] == abaikan_kode:
            continue
        cocok = re.fullmatch(rf'{re.escape(prefix)}(\d+)', row['kode'])
        if cocok:
            nomor.append(int(cocok.group(1)))
    return f'{prefix}{max(nomor, default=0) + 1:02d}'

def rapikan_kode_barang(conn):
    rows = conn.execute("SELECT rowid, kode, nama, tipe FROM barang ORDER BY rowid").fetchall()
    rencana = []
    hitungan = {}
    for row in rows:
        prefix = prefix_kode_nama(row['nama'], row['tipe'])
        hitungan[prefix] = hitungan.get(prefix, 0) + 1
        baru = f'{prefix}{hitungan[prefix]:02d}'
        rencana.append((row['rowid'], row['kode'], baru))

    for rowid, kode_lama, kode_baru in rencana:
        if kode_lama != kode_baru:
            conn.execute("UPDATE barang SET kode = ? WHERE rowid = ?", (f'TMP-{rowid}', rowid))
            conn.execute("UPDATE rekam_medis SET kode_item = ? WHERE kode_item = ?", (f'TMPH-{rowid}', kode_lama))
            try:
                conn.execute("UPDATE billing_detail SET kode_item = ? WHERE kode_item = ?", (f'TMPB-{rowid}', kode_lama))
            except sqlite3.OperationalError:
                pass
    for rowid, kode_lama, kode_baru in rencana:
        if kode_lama != kode_baru:
            conn.execute("UPDATE barang SET kode = ? WHERE rowid = ?", (kode_baru, rowid))
            conn.execute("UPDATE rekam_medis SET kode_item = ? WHERE kode_item = ?", (kode_baru, f'TMPH-{rowid}'))
            try:
                conn.execute("UPDATE billing_detail SET kode_item = ? WHERE kode_item = ?", (kode_baru, f'TMPB-{rowid}'))
            except sqlite3.OperationalError:
                pass

def posting_billing(conn, billing_id, no_rm, waktu):
    billing = conn.execute("SELECT diposting FROM billing WHERE id = ?", (billing_id,)).fetchone()
    if billing and billing['diposting']:
        return
    detail = conn.execute("SELECT * FROM billing_detail WHERE billing_id = ?", (billing_id,)).fetchall()
    for item in detail:
        if item['tipe'] == 'Produk':
            stok = conn.execute("SELECT stok FROM barang WHERE kode = ?", (item['kode_item'],)).fetchone()
            if not stok or stok['stok'] < item['qty']:
                sisa = stok['stok'] if stok else 0
                raise ValueError(f"Stok {item['nama_item']} tidak cukup. Sisa: {sisa}")
    for item in detail:
        if item['tipe'] == 'Produk':
            conn.execute("UPDATE barang SET stok = stok - ? WHERE kode = ?", (item['qty'], item['kode_item']))
        for _ in range(item['qty']):
            conn.execute(
                """INSERT INTO rekam_medis
                   (no_rm, kode_item, nama_item, tipe, harga, waktu, billing_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (no_rm, item['kode_item'], item['nama_item'], item['tipe'], item['harga'], waktu, billing_id)
            )
    conn.execute("UPDATE billing SET diposting = 1 WHERE id = ?", (billing_id,))

def batalkan_posting_billing(conn, billing_id):
    billing = conn.execute("SELECT diposting FROM billing WHERE id = ?", (billing_id,)).fetchone()
    if not billing or not billing['diposting']:
        return
    detail = conn.execute("SELECT * FROM billing_detail WHERE billing_id = ?", (billing_id,)).fetchall()
    for item in detail:
        if item['tipe'] == 'Produk':
            conn.execute("UPDATE barang SET stok = stok + ? WHERE kode = ?", (item['qty'], item['kode_item']))
    conn.execute("DELETE FROM rekam_medis WHERE billing_id = ?", (billing_id,))
    conn.execute("UPDATE billing SET diposting = 0 WHERE id = ?", (billing_id,))

def status_pembayaran(total, dibayar):
    if dibayar <= 0:
        return 'Belum Lunas'
    if dibayar < total:
        return 'Kurang Bayar'
    return 'Lunas'

def perbarui_pasien_tidak_aktif(conn):
    batas = (datetime.now() - timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')
    conn.execute(
        """UPDATE pasien
           SET aktif = 0
           WHERE aktif = 1
             AND MAX(
                   COALESCE((SELECT MAX(b.dibuat_pada) FROM billing b WHERE b.no_rm = pasien.no_rm), ''),
                   COALESCE((SELECT MAX(p.waktu) FROM pembayaran p JOIN billing b ON b.id=p.billing_id WHERE b.no_rm=pasien.no_rm), ''),
                   COALESCE(pasien.status_diubah_pada, ''),
                   COALESCE(pasien.terdaftar_pada, '')
                 ) < ?
             AND NOT EXISTS (
                   SELECT 1 FROM billing b
                   WHERE b.no_rm = pasien.no_rm AND b.status != 'Lunas'
                 )""",
        (batas,)
    )

def satukan_billing_aktif_ganda(conn):
    pasien_ganda = conn.execute(
        """SELECT no_rm FROM billing WHERE status != 'Lunas'
           GROUP BY no_rm HAVING COUNT(*) > 1"""
    ).fetchall()
    for pasien in pasien_ganda:
        bills = conn.execute(
            "SELECT id FROM billing WHERE no_rm = ? AND status != 'Lunas' ORDER BY id",
            (pasien['no_rm'],)
        ).fetchall()
        utama = bills[0]['id']
        batalkan_posting_billing(conn, utama)
        for bill in bills[1:]:
            lainnya = bill['id']
            batalkan_posting_billing(conn, lainnya)
            for item in conn.execute("SELECT * FROM billing_detail WHERE billing_id = ?", (lainnya,)).fetchall():
                ada = conn.execute(
                    "SELECT id FROM billing_detail WHERE billing_id=? AND kode_item=? AND harga=?",
                    (utama, item['kode_item'], item['harga'])
                ).fetchone()
                if ada:
                    conn.execute("UPDATE billing_detail SET qty=qty+?, subtotal=subtotal+? WHERE id=?", (item['qty'], item['subtotal'], ada['id']))
                else:
                    conn.execute(
                        """INSERT INTO billing_detail
                           (billing_id, kode_item, nama_item, tipe, harga, qty, subtotal)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (utama, item['kode_item'], item['nama_item'], item['tipe'], item['harga'], item['qty'], item['subtotal'])
                    )
            conn.execute("DELETE FROM rekam_medis WHERE billing_id = ?", (lainnya,))
            conn.execute("UPDATE pembayaran SET billing_id = ? WHERE billing_id = ?", (utama, lainnya))
            conn.execute("DELETE FROM billing_detail WHERE billing_id = ?", (lainnya,))
            conn.execute("DELETE FROM billing WHERE id = ?", (lainnya,))
        total = conn.execute("SELECT COALESCE(SUM(subtotal),0) total FROM billing_detail WHERE billing_id = ?", (utama,)).fetchone()['total']
        dibayar = conn.execute("SELECT COALESCE(SUM(nominal),0) jumlah FROM pembayaran WHERE billing_id = ?", (utama,)).fetchone()['jumlah']
        conn.execute(
            "UPDATE billing SET total=?, dibayar=?, kembalian=?, status=?, diposting=0 WHERE id=?",
            (total, dibayar, max(dibayar-total, 0), status_pembayaran(total, dibayar), utama)
        )

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS barang 
                 (kode TEXT PRIMARY KEY, nama TEXT, tipe TEXT, harga INTEGER, modal INTEGER DEFAULT 0, stok INTEGER,
                  aktif INTEGER DEFAULT 1)''')
    c.execute('''CREATE TABLE IF NOT EXISTS pasien
                 (no_rm TEXT PRIMARY KEY, nama TEXT, no_hp TEXT, alamat TEXT,
                  nik TEXT, rt TEXT, rw TEXT, desa TEXT, kecamatan TEXT, kota TEXT, provinsi TEXT,
                  aktif INTEGER DEFAULT 1, terdaftar_pada TEXT, status_diubah_pada TEXT,
                  tanggal_lahir TEXT, jenis_kelamin TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS rekam_medis 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, no_rm TEXT, kode_item TEXT, nama_item TEXT, tipe TEXT, harga INTEGER, waktu DATETIME DEFAULT CURRENT_TIMESTAMP, billing_id INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS billing
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, no_nota TEXT UNIQUE,
                  no_rm TEXT, nama_pasien TEXT, total INTEGER, status TEXT,
                  dibuat_pada TEXT, dibayar_pada TEXT, diposting INTEGER DEFAULT 0,
                  dibayar INTEGER DEFAULT 0, kembalian INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS billing_detail
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, billing_id INTEGER,
                  kode_item TEXT, nama_item TEXT, tipe TEXT, harga INTEGER,
                  qty INTEGER, subtotal INTEGER, modal_satuan INTEGER DEFAULT 0,
                  subtotal_modal INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS pembayaran
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, billing_id INTEGER,
                  nominal INTEGER, waktu TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS aset
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, kode TEXT UNIQUE, nama TEXT,
                  kategori TEXT, tanggal_beli TEXT, harga_perolehan INTEGER DEFAULT 0,
                  nilai_sisa INTEGER DEFAULT 0, masa_manfaat_bulan INTEGER DEFAULT 48,
                  kondisi TEXT DEFAULT 'Baik', lokasi TEXT, keterangan TEXT,
                  aktif INTEGER DEFAULT 1)''')
    c.execute('''CREATE TABLE IF NOT EXISTS pengeluaran
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, tanggal TEXT, kategori TEXT,
                  keterangan TEXT, nominal INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS karyawan
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, kode TEXT UNIQUE, nama TEXT,
                  jabatan TEXT, no_hp TEXT, nik TEXT, tempat_lahir TEXT, tanggal_lahir TEXT,
                  jenis_kelamin TEXT, email TEXT, alamat TEXT, tanggal_masuk TEXT,
                  status_kerja TEXT, kontak_darurat_nama TEXT, kontak_darurat_hp TEXT,
                  npwp TEXT, bpjs_kesehatan TEXT, bpjs_ketenagakerjaan TEXT,
                  bank TEXT, no_rekening TEXT, aktif INTEGER DEFAULT 1)''')
    c.execute('''CREATE TABLE IF NOT EXISTS absensi
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, karyawan_id INTEGER,
                  tanggal TEXT, jam_masuk TEXT, jam_pulang TEXT, status TEXT DEFAULT 'Hadir',
                  catatan TEXT, foto_masuk BLOB, foto_pulang BLOB,
                  latitude_masuk REAL, longitude_masuk REAL, akurasi_masuk REAL,
                  latitude_pulang REAL, longitude_pulang REAL, akurasi_pulang REAL,
                  UNIQUE(karyawan_id, tanggal))''')
    c.execute('''CREATE TABLE IF NOT EXISTS cache_alamat
                 (koordinat TEXT PRIMARY KEY, alamat TEXT, diperbarui_pada TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS akun
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE COLLATE NOCASE,
                  password_hash TEXT, nama TEXT, jabatan TEXT, karyawan_id INTEGER,
                  is_owner INTEGER DEFAULT 0, aktif INTEGER DEFAULT 1)''')
    c.execute('''CREATE TABLE IF NOT EXISTS jabatan_akses
                 (jabatan TEXT PRIMARY KEY COLLATE NOCASE, permissions TEXT DEFAULT '[]')''')
    c.execute('''CREATE TABLE IF NOT EXISTS app_settings
                 (kunci TEXT PRIMARY KEY, nilai TEXT)''')
    kolom_karyawan={row['name'] for row in c.execute("PRAGMA table_info(karyawan)").fetchall()}
    for nama_kolom in ('nama_panggilan','nik','tempat_lahir','tanggal_lahir','jenis_kelamin','email','alamat','tanggal_masuk','status_kerja','kontak_darurat_nama','kontak_darurat_hp','npwp','bpjs_kesehatan','bpjs_ketenagakerjaan','bank','no_rekening'):
        if nama_kolom not in kolom_karyawan: c.execute(f"ALTER TABLE karyawan ADD COLUMN {nama_kolom} TEXT")
    kolom_absensi={row['name'] for row in c.execute("PRAGMA table_info(absensi)").fetchall()}
    for nama_kolom,tipe in (
        ('foto_masuk','BLOB'),('foto_pulang','BLOB'),
        ('latitude_masuk','REAL'),('longitude_masuk','REAL'),('akurasi_masuk','REAL'),
        ('latitude_pulang','REAL'),('longitude_pulang','REAL'),('akurasi_pulang','REAL')):
        if nama_kolom not in kolom_absensi: c.execute(f"ALTER TABLE absensi ADD COLUMN {nama_kolom} {tipe}")
    for nama_kolom in ('alamat_masuk','alamat_pulang'):
        if nama_kolom not in kolom_absensi: c.execute(f"ALTER TABLE absensi ADD COLUMN {nama_kolom} TEXT")
    if not c.execute("SELECT 1 FROM app_settings WHERE kunci='owner_admin_migration_v1'").fetchone():
        c.execute("UPDATE akun SET username='admin_lama_' || id WHERE lower(username)='admin' AND is_owner=0")
        owner=c.execute("SELECT id FROM akun WHERE is_owner=1 ORDER BY id LIMIT 1").fetchone()
        if owner: c.execute("UPDATE akun SET username='admin',password_hash=?,nama='Owner',jabatan='Owner',aktif=1 WHERE id=?",(generate_password_hash('admin'),owner['id']))
        else: c.execute("INSERT INTO akun(username,password_hash,nama,jabatan,is_owner,aktif) VALUES('admin',?,'Owner','Owner',1,1)",(generate_password_hash('admin'),))
        c.execute("INSERT INTO app_settings(kunci,nilai) VALUES('owner_admin_migration_v1','selesai')")
    kolom_detail = {row['name'] for row in c.execute("PRAGMA table_info(billing_detail)").fetchall()}
    if 'modal_satuan' not in kolom_detail:
        c.execute("ALTER TABLE billing_detail ADD COLUMN modal_satuan INTEGER DEFAULT 0")
    if 'subtotal_modal' not in kolom_detail:
        c.execute("ALTER TABLE billing_detail ADD COLUMN subtotal_modal INTEGER DEFAULT 0")
    kolom_rm = {row['name'] for row in c.execute("PRAGMA table_info(rekam_medis)").fetchall()}
    if 'billing_id' not in kolom_rm:
        c.execute("ALTER TABLE rekam_medis ADD COLUMN billing_id INTEGER")
    kolom_billing = {row['name'] for row in c.execute("PRAGMA table_info(billing)").fetchall()}
    if 'diposting' not in kolom_billing:
        c.execute("ALTER TABLE billing ADD COLUMN diposting INTEGER DEFAULT 0")
        c.execute("UPDATE billing SET diposting = 1")
        for bill in c.execute("SELECT id FROM billing WHERE status = 'Belum Lunas'").fetchall():
            batalkan_posting_billing(conn, bill['id'])
    if 'dibayar' not in kolom_billing:
        c.execute("ALTER TABLE billing ADD COLUMN dibayar INTEGER DEFAULT 0")
        c.execute("UPDATE billing SET dibayar = total WHERE status = 'Lunas'")
    if 'kembalian' not in kolom_billing:
        c.execute("ALTER TABLE billing ADD COLUMN kembalian INTEGER DEFAULT 0")

    kolom_barang = {row['name'] for row in c.execute("PRAGMA table_info(barang)").fetchall()}
    if 'modal' not in kolom_barang:
        c.execute("ALTER TABLE barang ADD COLUMN modal INTEGER DEFAULT 0")
    if 'aktif' not in kolom_barang:
        c.execute("ALTER TABLE barang ADD COLUMN aktif INTEGER DEFAULT 1")
    c.execute("UPDATE barang SET modal = 0 WHERE modal IS NULL")
    c.execute("UPDATE barang SET aktif = 1 WHERE aktif IS NULL")

    data_awal = [
        ('FAC01', 'Facial Acne', 'Treatment', 250000, 0),
        ('LAS01', 'Laser Glowing', 'Treatment', 500000, 0),
        ('SER01', 'Serum Acne Glow', 'Produk', 150000, 20),
        ('SUN01', 'Sunscreen SPF 50', 'Produk', 85000, 50)
    ]
    for item in data_awal:
        c.execute("""INSERT INTO barang (kode, nama, tipe, harga, modal, stok)
                     SELECT ?, ?, ?, ?, 0, ?
                     WHERE NOT EXISTS (SELECT 1 FROM barang WHERE nama = ? AND tipe = ?)""",
                  (*item, item[1], item[2]))
    # Migrasi otomatis database lama tanpa menghapus data pasien.
    kolom_pasien = {row['name'] for row in c.execute("PRAGMA table_info(pasien)").fetchall()}
    for nama_kolom in ('nik', 'rt', 'rw', 'desa', 'kecamatan', 'kota', 'provinsi'):
        if nama_kolom not in kolom_pasien:
            c.execute(f"ALTER TABLE pasien ADD COLUMN {nama_kolom} TEXT")
    if 'aktif' not in kolom_pasien:
        c.execute("ALTER TABLE pasien ADD COLUMN aktif INTEGER DEFAULT 1")
    if 'terdaftar_pada' not in kolom_pasien:
        c.execute("ALTER TABLE pasien ADD COLUMN terdaftar_pada TEXT")
    if 'status_diubah_pada' not in kolom_pasien:
        c.execute("ALTER TABLE pasien ADD COLUMN status_diubah_pada TEXT")
    if 'tanggal_lahir' not in kolom_pasien:
        c.execute("ALTER TABLE pasien ADD COLUMN tanggal_lahir TEXT")
    if 'jenis_kelamin' not in kolom_pasien:
        c.execute("ALTER TABLE pasien ADD COLUMN jenis_kelamin TEXT")
    sekarang = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("UPDATE pasien SET aktif=1 WHERE aktif IS NULL")
    c.execute("UPDATE pasien SET terdaftar_pada=? WHERE terdaftar_pada IS NULL", (sekarang,))

    c.execute("INSERT OR IGNORE INTO pasien (no_rm, nama, no_hp, alamat) VALUES ('RM-001', 'Bagas Alwiyantoro', '08123456789', 'Pati, Jawa Tengah')")
    c.execute("INSERT OR IGNORE INTO pasien (no_rm, nama, no_hp, alamat) VALUES ('RM-002', 'Stevania Febriyanti', '08987654321', 'Pati, Jawa Tengah')")
    c.execute("UPDATE pasien SET aktif=1 WHERE aktif IS NULL")
    c.execute("UPDATE pasien SET terdaftar_pada=? WHERE terdaftar_pada IS NULL", (sekarang,))

    satukan_billing_aktif_ganda(conn)
    perbarui_pasien_tidak_aktif(conn)

    rapikan_kode_barang(conn)
    
    conn.commit()
    conn.close()

@app.route('/api/data', methods=['GET'])
def get_data():
    conn = get_db()
    perbarui_pasien_tidak_aktif(conn)
    conn.commit()
    barang = [dict(row) for row in conn.execute("SELECT * FROM barang ORDER BY tipe, nama").fetchall()]
    pasien = [dict(row) for row in conn.execute("SELECT * FROM pasien").fetchall()]
    conn.close()
    return jsonify({'barang': barang, 'pasien': pasien})

# --- SIMPAN BILLING DENGAN STATUS LUNAS / BELUM LUNAS ---
@app.route('/api/checkout', methods=['POST'])
def checkout():
    data = request.get_json(silent=True) or {}
    no_rm = data.get('no_rm')
    keranjang = data.get('keranjang', [])
    billing_id_lama = data.get('billing_id')
    try:
        uang_diterima = int(data.get('uang_diterima', 0) or 0)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "pesan": "Nominal uang diterima tidak valid!"}), 400
    
    if not no_rm or not keranjang:
        return jsonify({"status": "error", "pesan": "Pilih pasien dan masukkan item!"}), 400
    if uang_diterima < 0:
        return jsonify({"status": "error", "pesan": "Uang diterima tidak boleh negatif!"}), 400

    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        pasien = conn.execute("SELECT nama, aktif FROM pasien WHERE no_rm = ?", (no_rm,)).fetchone()
        if not pasien:
            raise ValueError('Pasien tidak ditemukan!')
        if not pasien['aktif']:
            raise ValueError('Pasien sedang nonaktif. Aktifkan kembali dari menu Database RM terlebih dahulu!')

        billing_lama = None
        edit_eksplisit = bool(billing_id_lama)
        if billing_id_lama:
            billing_lama = conn.execute("SELECT * FROM billing WHERE id = ?", (billing_id_lama,)).fetchone()
            if not billing_lama:
                raise ValueError('Billing yang akan diperbarui tidak ditemukan!')
            if billing_lama['status'] == 'Lunas':
                raise ValueError('Billing yang sudah lunas tidak dapat diubah!')
            batalkan_posting_billing(conn, billing_id_lama)
            conn.execute("DELETE FROM billing_detail WHERE billing_id = ?", (billing_id_lama,))
            conn.execute("DELETE FROM rekam_medis WHERE billing_id = ?", (billing_id_lama,))
        else:
            billing_lama = conn.execute(
                "SELECT * FROM billing WHERE no_rm = ? AND status != 'Lunas' ORDER BY id LIMIT 1",
                (no_rm,)
            ).fetchone()
            if billing_lama:
                batalkan_posting_billing(conn, billing_lama['id'])

        rincian = []
        total = 0 if edit_eksplisit or not billing_lama else billing_lama['total']
        for item_cart in keranjang:
            kode = str(item_cart.get('kode', '')).strip()
            qty = int(item_cart.get('qty', 0))
            if qty <= 0:
                raise ValueError('Jumlah item harus lebih dari 0!')
            item = conn.execute("SELECT nama, tipe, harga, modal, stok, aktif FROM barang WHERE kode = ?", (kode,)).fetchone()
            if not item:
                raise ValueError(f'Item {kode} tidak ditemukan!')
            if not item['aktif']:
                raise ValueError(f'{item["nama"]} sedang nonaktif dan tidak dapat dimasukkan ke billing!')
            subtotal = item['harga'] * qty
            total += subtotal
            rincian.append((kode, item['nama'], item['tipe'], item['harga'], qty, subtotal,
                            int(item['modal'] or 0), int(item['modal'] or 0) * qty))

        sekarang = datetime.now()
        waktu = sekarang.strftime('%Y-%m-%d %H:%M:%S')
        sudah_dibayar = int(billing_lama['dibayar'] or 0) if billing_lama else 0
        total_dibayar = sudah_dibayar + uang_diterima
        status = status_pembayaran(total, total_dibayar)
        kembalian = max(total_dibayar - total, 0)
        dibayar_pada = waktu if status == 'Lunas' else None
        if billing_lama:
            billing_id = billing_lama['id']
            no_nota = billing_lama['no_nota']
            conn.execute(
                "UPDATE billing SET no_rm=?, nama_pasien=?, total=?, status=?, dibayar_pada=?, diposting=0, dibayar=?, kembalian=? WHERE id=?",
                (no_rm, pasien['nama'], total, status, dibayar_pada, total_dibayar, kembalian, billing_id)
            )
        else:
            tanggal_kode = sekarang.strftime('%Y%m%d')
            jumlah_hari_ini = conn.execute("SELECT COUNT(*) jumlah FROM billing WHERE no_nota LIKE ?", (f'INV-{tanggal_kode}-%',)).fetchone()['jumlah']
            no_nota = f'INV-{tanggal_kode}-{jumlah_hari_ini + 1:03d}'
            cursor = conn.execute(
                """INSERT INTO billing
                   (no_nota, no_rm, nama_pasien, total, status, dibuat_pada, dibayar_pada, dibayar, kembalian)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (no_nota, no_rm, pasien['nama'], total, status, waktu, dibayar_pada, total_dibayar, kembalian)
            )
            billing_id = cursor.lastrowid

        for kode, nama, tipe, harga, qty, subtotal, modal_satuan, subtotal_modal in rincian:
            detail_ada = None if edit_eksplisit else conn.execute(
                "SELECT id, qty, subtotal FROM billing_detail WHERE billing_id = ? AND kode_item = ? AND harga = ?",
                (billing_id, kode, harga)
            ).fetchone()
            if detail_ada:
                conn.execute(
                    "UPDATE billing_detail SET qty = qty + ?, subtotal = subtotal + ?, subtotal_modal = subtotal_modal + ? WHERE id = ?",
                    (qty, subtotal, subtotal_modal, detail_ada['id'])
                )
            else:
                conn.execute(
                    """INSERT INTO billing_detail
                       (billing_id, kode_item, nama_item, tipe, harga, qty, subtotal, modal_satuan, subtotal_modal)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (billing_id, kode, nama, tipe, harga, qty, subtotal, modal_satuan, subtotal_modal)
                )
        if uang_diterima > 0:
            conn.execute(
                "INSERT INTO pembayaran (billing_id, nominal, waktu) VALUES (?, ?, ?)",
                (billing_id, uang_diterima, waktu)
            )
        if status == 'Lunas':
            posting_billing(conn, billing_id, no_rm, waktu)
        conn.commit()
        pesan = "Pesanan ditambahkan ke billing aktif." if billing_lama and not edit_eksplisit else "Billing berhasil disimpan."
        return jsonify({"status": "sukses", "pesan": pesan, "no_nota": no_nota,
                        "billing_id": billing_id, "status_bayar": status,
                        "dibayar": total_dibayar, "sisa": max(total-total_dibayar, 0),
                        "kembalian": kembalian})
    except ValueError as e:
        conn.rollback()
        return jsonify({"status": "error", "pesan": str(e)}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "pesan": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/edit_item', methods=['POST'])
def edit_item():
    data = request.get_json(silent=True) or {}
    kode = str(data.get('kode', '')).strip()
    nama = str(data.get('nama', '')).strip()
    try:
        harga = int(data.get('harga', 0))
        modal = int(data.get('modal', 0))
        stok = int(data.get('stok', 0))
    except (TypeError, ValueError):
        return jsonify({"status": "error", "pesan": "Harga jual, modal, atau stok tidak valid!"}), 400
    if not kode or not nama:
        return jsonify({"status": "error", "pesan": "Kode dan nama wajib diisi!"}), 400
    if harga < 0 or modal < 0 or stok < 0:
        return jsonify({"status": "error", "pesan": "Harga jual, modal, dan stok tidak boleh negatif!"}), 400
    
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("UPDATE barang SET nama = ?, harga = ?, modal = ?, stok = ? WHERE kode = ?", (nama, harga, modal, stok, kode))
        conn.commit()
        return jsonify({"status": "sukses"})
    except Exception as e:
        return jsonify({"status": "error", "pesan": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/tambah_item', methods=['POST'])
def tambah_item():
    data = request.get_json(silent=True) or {}
    nama = str(data.get('nama', '')).strip()
    tipe = str(data.get('tipe', '')).strip()

    try:
        harga = int(data.get('harga', 0))
        modal = int(data.get('modal', 0))
        stok = int(data.get('stok', 0)) if tipe == 'Produk' else 0
    except (TypeError, ValueError):
        return jsonify({'status': 'error', 'pesan': 'Harga jual, modal, atau stok tidak valid!'}), 400

    if tipe not in ('Produk', 'Treatment'):
        return jsonify({'status': 'error', 'pesan': 'Jenis item tidak valid!'}), 400
    if not nama:
        return jsonify({'status': 'error', 'pesan': 'Nama wajib diisi!'}), 400
    if harga < 0 or modal < 0 or stok < 0:
        return jsonify({'status': 'error', 'pesan': 'Harga jual, modal, dan stok tidak boleh negatif!'}), 400

    conn = get_db()
    try:
        kode = kode_nama_unik(conn, nama, tipe)
        conn.execute(
            "INSERT INTO barang (kode, nama, tipe, harga, modal, stok) VALUES (?, ?, ?, ?, ?, ?)",
            (kode, nama, tipe, harga, modal, stok)
        )
        conn.commit()
        return jsonify({'status': 'sukses', 'pesan': f'{tipe} berhasil ditambahkan.', 'kode': kode})
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'pesan': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/hapus_item/<kode>', methods=['DELETE'])
def hapus_item(kode):
    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        item = conn.execute("SELECT nama, aktif FROM barang WHERE kode = ?", (kode,)).fetchone()
        if not item:
            raise ValueError('Produk/Treatment tidak ditemukan!')
        billing_aktif = conn.execute(
            """SELECT 1 FROM billing_detail d JOIN billing b ON b.id = d.billing_id
               WHERE d.kode_item = ? AND b.status != 'Lunas' LIMIT 1""",
            (kode,)
        ).fetchone()
        if billing_aktif:
            raise ValueError('Item masih berada dalam billing yang belum lunas. Hapus item dari billing tersebut terlebih dahulu.')
        pernah_billing_lunas = conn.execute(
            """SELECT 1 FROM billing_detail d JOIN billing b ON b.id = d.billing_id
               WHERE d.kode_item = ? AND b.status = 'Lunas' LIMIT 1""",
            (kode,)
        ).fetchone()
        pernah_history = conn.execute("SELECT 1 FROM rekam_medis WHERE kode_item = ? LIMIT 1", (kode,)).fetchone()
        if pernah_billing_lunas or pernah_history:
            conn.execute("UPDATE barang SET aktif = 0 WHERE kode = ?", (kode,))
            conn.commit()
            return jsonify({
                'status': 'sukses',
                'aksi': 'nonaktif',
                'pesan': f"{item['nama']} pernah digunakan, sehingga dinonaktifkan dan tidak dihapus."
            })
        conn.execute("DELETE FROM barang WHERE kode = ?", (kode,))
        conn.commit()
        return jsonify({'status': 'sukses', 'aksi': 'hapus', 'pesan': f"{item['nama']} berhasil dihapus permanen."})
    except ValueError as e:
        conn.rollback()
        return jsonify({'status': 'error', 'pesan': str(e)}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'pesan': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/item/<kode>/status', methods=['POST'])
def ubah_status_item(kode):
    data = request.get_json(silent=True) or {}
    aktif = 1 if data.get('aktif') else 0
    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        item = conn.execute("SELECT nama, aktif FROM barang WHERE kode = ?", (kode,)).fetchone()
        if not item:
            raise ValueError('Produk/Treatment tidak ditemukan!')
        if not aktif:
            billing_aktif = conn.execute(
                """SELECT 1 FROM billing_detail d JOIN billing b ON b.id = d.billing_id
                   WHERE d.kode_item = ? AND b.status != 'Lunas' LIMIT 1""",
                (kode,)
            ).fetchone()
            if billing_aktif:
                raise ValueError('Item masih berada dalam billing yang belum lunas dan belum dapat dinonaktifkan.')
        conn.execute("UPDATE barang SET aktif = ? WHERE kode = ?", (aktif, kode))
        conn.commit()
        status_teks = 'diaktifkan kembali' if aktif else 'dinonaktifkan'
        return jsonify({'status': 'sukses', 'pesan': f"{item['nama']} berhasil {status_teks}."})
    except ValueError as e:
        conn.rollback()
        return jsonify({'status': 'error', 'pesan': str(e)}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'pesan': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/tambah_pasien', methods=['POST'])
def tambah_pasien():
    data = request.get_json(silent=True) or {}
    nama = str(data.get('nama', '')).strip()
    no_hp = str(data.get('no_hp', '')).strip()
    nik = ''.join(filter(str.isdigit, str(data.get('nik', '')).strip()))
    rt = str(data.get('rt', '')).strip()
    rw = str(data.get('rw', '')).strip()
    desa = str(data.get('desa', '')).strip()
    kecamatan = str(data.get('kecamatan', '')).strip()
    kota = str(data.get('kota', '')).strip()
    provinsi = str(data.get('provinsi', '')).strip()
    tanggal_lahir = str(data.get('tanggal_lahir', '')).strip()
    jenis_kelamin = str(data.get('jenis_kelamin', '')).strip()

    if not nama:
        return jsonify({'status': 'error', 'pesan': 'Nama pasien wajib diisi!'}), 400
    if nik and len(nik) != 16:
        return jsonify({'status': 'error', 'pesan': 'NIK harus 16 digit atau dikosongkan!'}), 400
    if jenis_kelamin not in ('', 'Perempuan', 'Laki-laki'):
        return jsonify({'status': 'error', 'pesan': 'Jenis kelamin tidak valid!'}), 400
    if tanggal_lahir:
        try:
            datetime.strptime(tanggal_lahir, '%Y-%m-%d')
        except ValueError:
            return jsonify({'status': 'error', 'pesan': 'Tanggal lahir tidak valid!'}), 400

    bagian_alamat = []
    if rt: bagian_alamat.append(f'RT {rt}')
    if rw: bagian_alamat.append(f'RW {rw}')
    if desa: bagian_alamat.append(f'Desa/Kel. {desa}')
    if kecamatan: bagian_alamat.append(f'Kec. {kecamatan}')
    if kota: bagian_alamat.append(kota)
    if provinsi: bagian_alamat.append(provinsi)
    alamat = ', '.join(bagian_alamat)

    conn = get_db()
    try:
        no_rm = buat_kode_otomatis(conn, 'pasien', 'no_rm', 'RM')
        conn.execute(
            """INSERT INTO pasien
               (no_rm, nama, no_hp, alamat, nik, rt, rw, desa, kecamatan, kota, provinsi,
                tanggal_lahir, jenis_kelamin,
                aktif, terdaftar_pada, status_diubah_pada)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
            (no_rm, nama, no_hp, alamat, nik or None, rt, rw, desa, kecamatan, kota, provinsi,
             tanggal_lahir or None, jenis_kelamin or None,
             datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
             datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        return jsonify({'status': 'sukses', 'pesan': 'Pasien berhasil ditambahkan.', 'no_rm': no_rm})
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'pesan': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/pasien/<no_rm>', methods=['PUT'])
def edit_pasien(no_rm):
    data = request.get_json(silent=True) or {}
    nama = str(data.get('nama', '')).strip()
    no_hp = str(data.get('no_hp', '')).strip()
    nik = ''.join(filter(str.isdigit, str(data.get('nik', '')).strip()))
    rt = str(data.get('rt', '')).strip()
    rw = str(data.get('rw', '')).strip()
    desa = str(data.get('desa', '')).strip()
    kecamatan = str(data.get('kecamatan', '')).strip()
    kota = str(data.get('kota', '')).strip()
    provinsi = str(data.get('provinsi', '')).strip()
    tanggal_lahir = str(data.get('tanggal_lahir', '')).strip()
    jenis_kelamin = str(data.get('jenis_kelamin', '')).strip()

    if not nama:
        return jsonify({'status': 'error', 'pesan': 'Nama pasien wajib diisi!'}), 400
    if nik and len(nik) != 16:
        return jsonify({'status': 'error', 'pesan': 'NIK harus 16 digit atau dikosongkan!'}), 400
    if jenis_kelamin not in ('', 'Perempuan', 'Laki-laki'):
        return jsonify({'status': 'error', 'pesan': 'Jenis kelamin tidak valid!'}), 400
    if tanggal_lahir:
        try:
            datetime.strptime(tanggal_lahir, '%Y-%m-%d')
        except ValueError:
            return jsonify({'status': 'error', 'pesan': 'Tanggal lahir tidak valid!'}), 400

    bagian_alamat = []
    if rt: bagian_alamat.append(f'RT {rt}')
    if rw: bagian_alamat.append(f'RW {rw}')
    if desa: bagian_alamat.append(f'Desa/Kel. {desa}')
    if kecamatan: bagian_alamat.append(f'Kec. {kecamatan}')
    if kota: bagian_alamat.append(kota)
    if provinsi: bagian_alamat.append(provinsi)
    alamat = ', '.join(bagian_alamat)

    conn = get_db()
    try:
        pasien = conn.execute("SELECT no_rm FROM pasien WHERE no_rm = ?", (no_rm,)).fetchone()
        if not pasien:
            return jsonify({'status': 'error', 'pesan': 'Pasien tidak ditemukan!'}), 404
        conn.execute(
            """UPDATE pasien SET
               nama=?, no_hp=?, alamat=?, nik=?, rt=?, rw=?, desa=?, kecamatan=?,
               kota=?, provinsi=?, tanggal_lahir=?, jenis_kelamin=?
               WHERE no_rm=?""",
            (nama, no_hp, alamat, nik or None, rt, rw, desa, kecamatan, kota,
             provinsi, tanggal_lahir or None, jenis_kelamin or None, no_rm)
        )
        conn.commit()
        return jsonify({'status': 'sukses', 'pesan': 'Profil pasien berhasil diperbarui.', 'no_rm': no_rm})
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'pesan': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/history/<no_rm>', methods=['GET'])
def get_history(no_rm):
    conn = get_db()
    history = [dict(row) for row in conn.execute("SELECT nama_item, tipe, harga, waktu FROM rekam_medis WHERE no_rm = ? ORDER BY waktu DESC", (no_rm,)).fetchall()]
    conn.close()
    return jsonify(history)

@app.route('/api/pasien/<no_rm>/status', methods=['POST'])
def ubah_status_pasien(no_rm):
    data = request.get_json(silent=True) or {}
    aktif = 1 if data.get('aktif') else 0
    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        pasien = conn.execute("SELECT nama FROM pasien WHERE no_rm = ?", (no_rm,)).fetchone()
        if not pasien:
            raise ValueError('Pasien tidak ditemukan!')
        if not aktif and conn.execute(
            "SELECT 1 FROM billing WHERE no_rm=? AND status != 'Lunas' LIMIT 1", (no_rm,)
        ).fetchone():
            raise ValueError('Pasien masih mempunyai tagihan yang belum lunas dan tidak dapat dinonaktifkan.')
        waktu = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("UPDATE pasien SET aktif=?, status_diubah_pada=? WHERE no_rm=?", (aktif, waktu, no_rm))
        conn.commit()
        teks = 'diaktifkan kembali' if aktif else 'dinonaktifkan'
        return jsonify({'status':'sukses', 'pesan':f"{pasien['nama']} berhasil {teks}."})
    except ValueError as e:
        conn.rollback()
        return jsonify({'status':'error', 'pesan':str(e)}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({'status':'error', 'pesan':str(e)}), 500
    finally:
        conn.close()

@app.route('/api/billing', methods=['GET'])
def daftar_billing():
    conn = get_db()
    rows = [dict(row) for row in conn.execute(
        """SELECT id, no_nota, no_rm, nama_pasien, total, status,
                  dibuat_pada, dibayar_pada, dibayar, kembalian,
                  MAX(total - dibayar, 0) AS sisa
           FROM billing ORDER BY id DESC"""
    ).fetchall()]
    conn.close()
    return jsonify(rows)

@app.route('/api/billing/<int:billing_id>', methods=['GET'])
def detail_billing(billing_id):
    conn = get_db()
    billing = conn.execute("SELECT * FROM billing WHERE id = ?", (billing_id,)).fetchone()
    if not billing:
        conn.close()
        return jsonify({'status': 'error', 'pesan': 'Billing tidak ditemukan!'}), 404
    detail = [dict(row) for row in conn.execute(
        "SELECT kode_item, nama_item, tipe, harga, qty, subtotal FROM billing_detail WHERE billing_id = ? ORDER BY id",
        (billing_id,)
    ).fetchall()]
    pembayaran = [dict(row) for row in conn.execute(
        "SELECT nominal, waktu FROM pembayaran WHERE billing_id=? ORDER BY id", (billing_id,)
    ).fetchall()]
    conn.close()
    return jsonify({'billing': dict(billing), 'detail': detail, 'pembayaran': pembayaran})

@app.route('/api/billing/<int:billing_id>/bayar', methods=['POST'])
def tambah_pembayaran(billing_id):
    data = request.get_json(silent=True) or {}
    try:
        nominal = int(data.get('nominal', 0))
    except (TypeError, ValueError):
        return jsonify({'status':'error', 'pesan':'Nominal pembayaran tidak valid!'}), 400
    if nominal <= 0:
        return jsonify({'status':'error', 'pesan':'Nominal pembayaran harus lebih dari 0!'}), 400
    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        billing = conn.execute("SELECT * FROM billing WHERE id=?", (billing_id,)).fetchone()
        if not billing:
            raise ValueError('Billing tidak ditemukan!')
        if billing['status'] == 'Lunas':
            raise ValueError('Billing sudah lunas dan tidak dapat menerima pembayaran lagi!')
        waktu = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        total_dibayar = int(billing['dibayar'] or 0) + nominal
        status = status_pembayaran(billing['total'], total_dibayar)
        kembalian = max(total_dibayar - billing['total'], 0)
        conn.execute("INSERT INTO pembayaran (billing_id, nominal, waktu) VALUES (?, ?, ?)",
                     (billing_id, nominal, waktu))
        if status == 'Lunas':
            posting_billing(conn, billing_id, billing['no_rm'], waktu)
        conn.execute(
            "UPDATE billing SET dibayar=?, kembalian=?, status=?, dibayar_pada=? WHERE id=?",
            (total_dibayar, kembalian, status, waktu if status == 'Lunas' else None, billing_id)
        )
        conn.commit()
        return jsonify({'status':'sukses', 'pesan':'Pembayaran berhasil dicatat.',
                        'status_bayar':status, 'dibayar':total_dibayar,
                        'sisa':max(billing['total']-total_dibayar, 0), 'kembalian':kembalian})
    except ValueError as e:
        conn.rollback()
        return jsonify({'status':'error', 'pesan':str(e)}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({'status':'error', 'pesan':str(e)}), 500
    finally:
        conn.close()

@app.route('/api/billing/<int:billing_id>/lunas', methods=['POST'])
def lunasi_billing(billing_id):
    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        billing = conn.execute("SELECT * FROM billing WHERE id = ?", (billing_id,)).fetchone()
        if not billing:
            raise ValueError('Billing tidak ditemukan!')
        if billing['status'] == 'Lunas':
            conn.commit()
            return jsonify({'status': 'sukses', 'pesan': 'Billing sudah lunas.'})
        waktu = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        kekurangan = max(int(billing['total']) - int(billing['dibayar'] or 0), 0)
        if kekurangan:
            conn.execute("INSERT INTO pembayaran (billing_id, nominal, waktu) VALUES (?, ?, ?)",
                         (billing_id, kekurangan, waktu))
        posting_billing(conn, billing_id, billing['no_rm'], waktu)
        conn.execute("UPDATE billing SET status='Lunas', dibayar_pada=?, dibayar=total, kembalian=0 WHERE id=?", (waktu, billing_id))
        conn.commit()
        return jsonify({'status': 'sukses', 'pesan': 'Billing sudah ditandai lunas.'})
    except ValueError as e:
        conn.rollback()
        return jsonify({'status': 'error', 'pesan': str(e)}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'pesan': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/billing/<int:billing_id>', methods=['DELETE'])
def hapus_billing(billing_id):
    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        billing = conn.execute("SELECT * FROM billing WHERE id = ?", (billing_id,)).fetchone()
        if not billing:
            raise ValueError('Billing tidak ditemukan!')
        if billing['status'] == 'Lunas':
            raise ValueError('Billing yang sudah lunas tidak dapat dihapus!')
        batalkan_posting_billing(conn, billing_id)
        conn.execute("DELETE FROM rekam_medis WHERE billing_id = ?", (billing_id,))
        conn.execute("DELETE FROM pembayaran WHERE billing_id = ?", (billing_id,))
        conn.execute("DELETE FROM billing_detail WHERE billing_id = ?", (billing_id,))
        conn.execute("DELETE FROM billing WHERE id = ?", (billing_id,))
        conn.commit()
        return jsonify({'status': 'sukses', 'pesan': 'Billing belum lunas berhasil dihapus.'})
    except ValueError as e:
        conn.rollback()
        return jsonify({'status': 'error', 'pesan': str(e)}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'pesan': str(e)}), 500
    finally:
        conn.close()

# --- ADMINISTRASI: LAPORAN, ASET, PENGELUARAN, DAN ABSENSI ---
@app.route('/api/laporan-bulanan')
def laporan_bulanan():
    bulan = request.args.get('bulan') or sekarang().strftime('%Y-%m')
    if not re.fullmatch(r'\d{4}-\d{2}', bulan):
        return jsonify({'status':'error', 'pesan':'Format bulan tidak valid.'}), 400
    awal, akhir = f'{bulan}-01 00:00:00', f'{bulan}-{monthrange(int(bulan[:4]), int(bulan[5:]))[1]} 23:59:59'
    conn = get_db()
    ringkas = conn.execute(
        """SELECT COUNT(*) transaksi, COALESCE(SUM(b.total),0) omzet,
                  COALESCE(SUM((SELECT SUM(d.subtotal_modal) FROM billing_detail d WHERE d.billing_id=b.id)),0) modal
           FROM billing b WHERE b.status='Lunas' AND b.dibayar_pada BETWEEN ? AND ?""", (awal, akhir)).fetchone()
    pengeluaran = conn.execute(
        "SELECT COALESCE(SUM(nominal),0) jumlah FROM pengeluaran WHERE tanggal BETWEEN ? AND ?",
        (awal[:10], akhir[:10])).fetchone()['jumlah']
    aset = [dict(r) for r in conn.execute("SELECT * FROM aset WHERE aktif=1 AND tanggal_beli<=?", (akhir[:10],)).fetchall()]
    penyusutan = sum(max(int(a['harga_perolehan'] or 0)-int(a['nilai_sisa'] or 0), 0) /
                     max(int(a['masa_manfaat_bulan'] or 1), 1) for a in aset)
    omzet, modal = int(ringkas['omzet']), int(ringkas['modal'])
    detail = [dict(r) for r in conn.execute(
        """SELECT b.no_nota, b.dibayar_pada, b.nama_pasien, b.total,
                  COALESCE(SUM(d.subtotal_modal),0) modal,
                  b.total-COALESCE(SUM(d.subtotal_modal),0) laba_kotor
           FROM billing b LEFT JOIN billing_detail d ON d.billing_id=b.id
           WHERE b.status='Lunas' AND b.dibayar_pada BETWEEN ? AND ?
           GROUP BY b.id ORDER BY b.dibayar_pada DESC""", (awal, akhir)).fetchall()]
    conn.close()
    return jsonify({'bulan':bulan, 'transaksi':ringkas['transaksi'], 'omzet':omzet, 'modal':modal,
                    'laba_kotor':omzet-modal, 'pengeluaran':int(pengeluaran),
                    'penyusutan':round(penyusutan), 'laba_bersih':round(omzet-modal-int(pengeluaran)-penyusutan),
                    'detail':detail})

@app.route('/api/aset', methods=['GET', 'POST'])
def kelola_aset():
    conn = get_db()
    if request.method == 'GET':
        rows = [dict(r) for r in conn.execute("SELECT * FROM aset ORDER BY aktif DESC, tanggal_beli DESC, id DESC").fetchall()]
        conn.close(); return jsonify(rows)
    data = request.get_json(silent=True) or {}
    try:
        nama = str(data.get('nama','')).strip()
        if not nama: raise ValueError('Nama aset wajib diisi.')
        harga, sisa, manfaat = int(data.get('harga_perolehan',0)), int(data.get('nilai_sisa',0)), int(data.get('masa_manfaat_bulan',48))
        if harga < 0 or sisa < 0 or manfaat < 1: raise ValueError('Nilai aset tidak valid.')
        kode = buat_kode_otomatis(conn, 'aset', 'kode', 'AST')
        conn.execute("""INSERT INTO aset(kode,nama,kategori,tanggal_beli,harga_perolehan,nilai_sisa,masa_manfaat_bulan,kondisi,lokasi,keterangan)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""", (kode,nama,data.get('kategori','Peralatan'),data.get('tanggal_beli') or sekarang().strftime('%Y-%m-%d'),harga,sisa,manfaat,data.get('kondisi','Baik'),data.get('lokasi',''),data.get('keterangan','')))
        conn.commit(); return jsonify({'status':'sukses','pesan':f'Aset {nama} berhasil disimpan.','kode':kode})
    except ValueError as e:
        return jsonify({'status':'error','pesan':str(e)}),400
    finally: conn.close()

@app.route('/api/aset/<int:item_id>', methods=['PUT', 'DELETE'])
def ubah_aset(item_id):
    conn=get_db(); data=request.get_json(silent=True) or {}
    try:
        if request.method=='DELETE':
            conn.execute("UPDATE aset SET aktif=0 WHERE id=?",(item_id,)); pesan='Aset berhasil diarsipkan.'
        else:
            harga,sisa,manfaat=int(data.get('harga_perolehan',0)),int(data.get('nilai_sisa',0)),int(data.get('masa_manfaat_bulan',48))
            if not str(data.get('nama','')).strip() or harga<0 or sisa<0 or manfaat<1: raise ValueError('Data aset tidak valid.')
            conn.execute("""UPDATE aset SET nama=?,kategori=?,tanggal_beli=?,harga_perolehan=?,nilai_sisa=?,masa_manfaat_bulan=?,kondisi=?,lokasi=?,keterangan=? WHERE id=?""",
                         (str(data.get('nama')).strip(),data.get('kategori','Peralatan'),data.get('tanggal_beli'),harga,sisa,manfaat,data.get('kondisi','Baik'),data.get('lokasi',''),data.get('keterangan',''),item_id)); pesan='Data aset berhasil diperbarui.'
        conn.commit(); return jsonify({'status':'sukses','pesan':pesan})
    except ValueError as e: return jsonify({'status':'error','pesan':str(e)}),400
    finally: conn.close()

@app.route('/api/aset/<int:item_id>/status', methods=['POST'])
def status_aset(item_id):
    data=request.get_json(silent=True) or {};aktif=1 if data.get('aktif') else 0
    conn=get_db()
    try:
        aset=conn.execute("SELECT nama FROM aset WHERE id=?",(item_id,)).fetchone()
        if not aset: return jsonify({'status':'error','pesan':'Aset tidak ditemukan.'}),404
        conn.execute("UPDATE aset SET aktif=? WHERE id=?",(aktif,item_id));conn.commit()
        return jsonify({'status':'sukses','pesan':f"{aset['nama']} berhasil {'dilepas dari arsip' if aktif else 'diarsipkan'}."})
    finally: conn.close()

@app.route('/api/pengeluaran', methods=['GET','POST'])
def kelola_pengeluaran():
    conn=get_db()
    if request.method=='GET':
        bulan=request.args.get('bulan') or sekarang().strftime('%Y-%m')
        rows=[dict(r) for r in conn.execute("SELECT * FROM pengeluaran WHERE tanggal LIKE ? ORDER BY tanggal DESC,id DESC",(bulan+'%',)).fetchall()]
        conn.close(); return jsonify(rows)
    data=request.get_json(silent=True) or {}
    try:
        nominal=int(data.get('nominal',0)); ket=str(data.get('keterangan','')).strip()
        if nominal<=0 or not ket: raise ValueError('Keterangan dan nominal pengeluaran wajib diisi.')
        conn.execute("INSERT INTO pengeluaran(tanggal,kategori,keterangan,nominal) VALUES(?,?,?,?)",(data.get('tanggal') or sekarang().strftime('%Y-%m-%d'),data.get('kategori','Operasional'),ket,nominal)); conn.commit()
        return jsonify({'status':'sukses','pesan':'Pengeluaran berhasil dicatat.'})
    except ValueError as e: return jsonify({'status':'error','pesan':str(e)}),400
    finally: conn.close()

@app.route('/api/pengeluaran/<int:item_id>', methods=['PUT','DELETE'])
def hapus_pengeluaran(item_id):
    conn=get_db()
    try:
        ada=conn.execute("SELECT id FROM pengeluaran WHERE id=?",(item_id,)).fetchone()
        if not ada: return jsonify({'status':'error','pesan':'Pengeluaran tidak ditemukan.'}),404
        if request.method=='DELETE':
            conn.execute("DELETE FROM pengeluaran WHERE id=?",(item_id,));pesan='Pengeluaran berhasil dihapus.'
        else:
            data=request.get_json(silent=True) or {};nominal=int(data.get('nominal',0));ket=str(data.get('keterangan','')).strip()
            if nominal<=0 or not ket: raise ValueError('Keterangan dan nominal wajib diisi.')
            conn.execute("UPDATE pengeluaran SET tanggal=?,kategori=?,keterangan=?,nominal=? WHERE id=?",(data.get('tanggal'),data.get('kategori','Operasional'),ket,nominal,item_id));pesan='Pengeluaran berhasil diperbarui.'
        conn.commit();return jsonify({'status':'sukses','pesan':pesan})
    except ValueError as e: return jsonify({'status':'error','pesan':str(e)}),400
    finally: conn.close()

@app.route('/api/karyawan', methods=['GET','POST'])
def kelola_karyawan():
    conn=get_db()
    if request.method=='GET':
        rows=[dict(r) for r in conn.execute("SELECT k.*,a.username FROM karyawan k LEFT JOIN akun a ON a.karyawan_id=k.id ORDER BY k.aktif DESC,k.nama").fetchall()]; conn.close(); return jsonify(rows)
    data=request.get_json(silent=True) or {}; nama=str(data.get('nama','')).strip();panggilan=str(data.get('nama_panggilan','')).strip();jabatan=str(data.get('jabatan','')).strip();password=str(data.get('password',''))
    try:
        if not nama or not panggilan or not jabatan: raise ValueError('Nama lengkap, nama panggilan, dan jabatan wajib diisi.')
        if len(password)<8: raise ValueError('Password awal minimal 8 karakter.')
        nik=str(data.get('nik','')).strip()
        if nik and (not nik.isdigit() or len(nik)!=16): raise ValueError('NIK harus terdiri dari 16 angka.')
        if nik and conn.execute("SELECT 1 FROM karyawan WHERE nik=?",(nik,)).fetchone(): raise ValueError('NIK sudah digunakan karyawan lain.')
        conn.execute('BEGIN IMMEDIATE');kode=buat_kode_otomatis(conn,'karyawan','kode','KRY')
        username=username_dari_panggilan(conn,panggilan)
        kolom=('kode','nama','nama_panggilan','jabatan','no_hp','nik','tempat_lahir','tanggal_lahir','jenis_kelamin','email','alamat','tanggal_masuk','status_kerja','kontak_darurat_nama','kontak_darurat_hp','npwp','bpjs_kesehatan','bpjs_ketenagakerjaan','bank','no_rekening')
        nilai=(kode,nama,panggilan,jabatan,data.get('no_hp',''),data.get('nik',''),data.get('tempat_lahir',''),data.get('tanggal_lahir',''),data.get('jenis_kelamin',''),data.get('email',''),data.get('alamat',''),data.get('tanggal_masuk',''),data.get('status_kerja',''),data.get('kontak_darurat_nama',''),data.get('kontak_darurat_hp',''),data.get('npwp',''),data.get('bpjs_kesehatan',''),data.get('bpjs_ketenagakerjaan',''),data.get('bank',''),data.get('no_rekening',''))
        cur=conn.execute(f"INSERT INTO karyawan({','.join(kolom)}) VALUES({','.join('?' for _ in kolom)})",nilai)
        conn.execute("INSERT INTO akun(username,password_hash,nama,jabatan,karyawan_id) VALUES(?,?,?,?,?)",(username,generate_password_hash(password),nama,jabatan,cur.lastrowid));conn.commit()
        return jsonify({'status':'sukses','pesan':f'Karyawan dan akun {nama} berhasil ditambahkan.','kode':kode})
    except (ValueError,sqlite3.IntegrityError) as e:
        conn.rollback();return jsonify({'status':'error','pesan':'Username sudah digunakan.' if isinstance(e,sqlite3.IntegrityError) else str(e)}),400
    finally: conn.close()

@app.route('/api/karyawan-ringkas')
def karyawan_ringkas():
    conn=get_db();rows=[dict(r) for r in conn.execute("SELECT id,kode,nama,jabatan,aktif FROM karyawan WHERE aktif=1 ORDER BY nama").fetchall()];conn.close();return jsonify(rows)

@app.route('/api/karyawan/<int:item_id>',methods=['PUT'])
def edit_karyawan_admin(item_id):
    data=request.get_json(silent=True) or {};conn=get_db()
    try:
        k=conn.execute("SELECT * FROM karyawan WHERE id=?",(item_id,)).fetchone()
        if not k: raise ValueError('Karyawan tidak ditemukan.')
        nama=str(data.get('nama','')).strip();panggilan=str(data.get('nama_panggilan','')).strip();jabatan=str(data.get('jabatan','')).strip()
        if not nama or not panggilan or not jabatan: raise ValueError('Nama lengkap, nama panggilan, dan jabatan wajib diisi.')
        nik=str(data.get('nik','')).strip()
        if nik and (not nik.isdigit() or len(nik)!=16): raise ValueError('NIK harus terdiri dari 16 angka.')
        if nik and conn.execute("SELECT 1 FROM karyawan WHERE nik=? AND id!=?",(nik,item_id)).fetchone(): raise ValueError('NIK sudah digunakan karyawan lain.')
        kolom=('nama','nama_panggilan','jabatan','no_hp','nik','tempat_lahir','tanggal_lahir','jenis_kelamin','email','alamat','tanggal_masuk','status_kerja','kontak_darurat_nama','kontak_darurat_hp','npwp','bpjs_kesehatan','bpjs_ketenagakerjaan','bank','no_rekening')
        nilai=tuple(data.get(x,'') for x in kolom)
        conn.execute(f"UPDATE karyawan SET {','.join(x+'=?' for x in kolom)} WHERE id=?",nilai+(item_id,))
        akun=conn.execute("SELECT id FROM akun WHERE karyawan_id=?",(item_id,)).fetchone()
        if akun:
            username=username_dari_panggilan(conn,panggilan,akun['id'])
            conn.execute("UPDATE akun SET username=?,nama=?,jabatan=? WHERE id=?",(username,nama,jabatan,akun['id']))
        conn.commit();return jsonify({'status':'sukses','pesan':'Data karyawan berhasil diperbarui.'})
    except (ValueError,sqlite3.IntegrityError) as e:
        conn.rollback();return jsonify({'status':'error','pesan':'Username atau NIK sudah digunakan.' if isinstance(e,sqlite3.IntegrityError) else str(e)}),400
    finally: conn.close()

@app.route('/api/karyawan/<int:item_id>/reset-password',methods=['POST'])
def reset_password_karyawan(item_id):
    data=request.get_json(silent=True) or {};password=str(data.get('password',''))
    if len(password)<8: return jsonify({'status':'error','pesan':'Password baru minimal 8 karakter.'}),400
    conn=get_db();akun=conn.execute("SELECT a.id,k.nama FROM akun a JOIN karyawan k ON k.id=a.karyawan_id WHERE k.id=?",(item_id,)).fetchone()
    if not akun: conn.close();return jsonify({'status':'error','pesan':'Akun karyawan tidak ditemukan.'}),404
    conn.execute("UPDATE akun SET password_hash=? WHERE id=?",(generate_password_hash(password),akun['id']));conn.commit();conn.close()
    return jsonify({'status':'sukses','pesan':f"Password {akun['nama']} berhasil direset."})

@app.route('/api/karyawan/<int:item_id>/status', methods=['POST'])
def status_karyawan(item_id):
    data=request.get_json(silent=True) or {};aktif=1 if data.get('aktif') else 0
    conn=get_db()
    try:
        k=conn.execute("SELECT nama FROM karyawan WHERE id=?",(item_id,)).fetchone()
        if not k: return jsonify({'status':'error','pesan':'Karyawan tidak ditemukan.'}),404
        conn.execute("UPDATE karyawan SET aktif=? WHERE id=?",(aktif,item_id));conn.execute("UPDATE akun SET aktif=? WHERE karyawan_id=?",(aktif,item_id));conn.commit()
        return jsonify({'status':'sukses','pesan':f"{k['nama']} berhasil {'diaktifkan' if aktif else 'dinonaktifkan'}."})
    finally: conn.close()

@app.route('/api/karyawan/<int:item_id>/absensi')
def history_absensi_karyawan(item_id):
    bulan=request.args.get('bulan') or sekarang().strftime('%Y-%m');conn=get_db()
    k=conn.execute("SELECT * FROM karyawan WHERE id=?",(item_id,)).fetchone()
    if not k: conn.close();return jsonify({'status':'error','pesan':'Karyawan tidak ditemukan.'}),404
    rows=[dict(r) for r in conn.execute("""SELECT id,karyawan_id,tanggal,jam_masuk,jam_pulang,status,catatan,
        latitude_masuk,longitude_masuk,akurasi_masuk,alamat_masuk,
        latitude_pulang,longitude_pulang,akurasi_pulang,alamat_pulang,
        CASE WHEN foto_masuk IS NOT NULL THEN 1 ELSE 0 END AS ada_foto_masuk,
        CASE WHEN foto_pulang IS NOT NULL THEN 1 ELSE 0 END AS ada_foto_pulang
        FROM absensi WHERE karyawan_id=? AND tanggal LIKE ? ORDER BY tanggal DESC""",(item_id,bulan+'%')).fetchall()];conn.close()
    return jsonify({'karyawan':dict(k),'bulan':bulan,'history':rows})

@app.route('/api/geocode/reverse')
def alamat_dari_koordinat():
    """Terjemahkan GPS menjadi alamat; cache lokal mencegah permintaan berulang."""
    try:
        latitude=float(request.args.get('lat'));longitude=float(request.args.get('lon'))
        if not (-90<=latitude<=90 and -180<=longitude<=180): raise ValueError
    except (ValueError,TypeError):
        return jsonify({'status':'error','pesan':'Koordinat tidak valid.'}),400
    kunci=f'{latitude:.4f},{longitude:.4f}'
    conn=get_db();cache=conn.execute("SELECT alamat FROM cache_alamat WHERE koordinat=?",(kunci,)).fetchone()
    if cache:
        conn.close();return jsonify({'status':'sukses','alamat':cache['alamat'],'sumber':'cache'})
    try:
        query=urllib.parse.urlencode({'format':'jsonv2','lat':f'{latitude:.7f}','lon':f'{longitude:.7f}','zoom':18,'addressdetails':1,'accept-language':'id'})
        req=urllib.request.Request('https://nominatim.openstreetmap.org/reverse?'+query,headers={'User-Agent':'ETH-Aesthetic-Attendance/1.0','Accept':'application/json'})
        with urllib.request.urlopen(req,timeout=10) as respons:
            hasil=json.loads(respons.read().decode('utf-8'))
        alamat=str(hasil.get('display_name') or '').strip()[:500]
        if not alamat: raise ValueError('Alamat tidak ditemukan')
        conn.execute("INSERT OR REPLACE INTO cache_alamat(koordinat,alamat,diperbarui_pada) VALUES(?,?,?)",(kunci,alamat,sekarang().isoformat()));conn.commit();conn.close()
        return jsonify({'status':'sukses','alamat':alamat,'sumber':'peta'})
    except Exception:
        conn.close()
        return jsonify({'status':'error','pesan':'Nama alamat belum tersedia. Koordinat GPS tetap dapat digunakan.'}),503

@app.route('/api/absensi/<int:item_id>/foto/<jenis>')
def bukti_foto_absensi(item_id,jenis):
    if jenis not in {'masuk','pulang'}: return jsonify({'status':'error','pesan':'Jenis bukti tidak valid.'}),400
    conn=get_db();row=conn.execute(f"SELECT foto_{jenis} AS foto FROM absensi WHERE id=?",(item_id,)).fetchone();conn.close()
    if not row or not row['foto']: return jsonify({'status':'error','pesan':'Foto bukti tidak ditemukan.'}),404
    return send_file(io.BytesIO(row['foto']),mimetype='image/jpeg',max_age=0)

def baca_bukti_absensi(data):
    foto=str(data.get('foto',''))
    if ',' not in foto: raise ValueError('Ambil selfie terbaru terlebih dahulu.')
    kepala,isi=foto.split(',',1)
    if not kepala.startswith('data:image/'): raise ValueError('Format selfie tidak valid.')
    try: foto_bytes=base64.b64decode(isi,validate=True)
    except Exception: raise ValueError('Data selfie rusak. Silakan ambil ulang.')
    if len(foto_bytes)<1000 or len(foto_bytes)>2_000_000: raise ValueError('Ukuran selfie tidak valid. Silakan ambil ulang.')
    try:
        latitude=float(data.get('latitude'));longitude=float(data.get('longitude'));akurasi=float(data.get('akurasi'))
    except (ValueError,TypeError): raise ValueError('Lokasi belum berhasil didapatkan.')
    if not (-90<=latitude<=90 and -180<=longitude<=180) or akurasi<0: raise ValueError('Koordinat lokasi tidak valid.')
    alamat=str(data.get('alamat') or '').strip()[:500]
    return foto_bytes,latitude,longitude,akurasi,alamat

@app.route('/api/absensi', methods=['GET','POST'])
def kelola_absensi():
    conn=get_db()
    if request.method=='GET':
        bulan=request.args.get('bulan') or sekarang().strftime('%Y-%m')
        rows=[dict(r) for r in conn.execute("""SELECT a.id,a.karyawan_id,a.tanggal,a.jam_masuk,a.jam_pulang,a.status,a.catatan,
            a.latitude_masuk,a.longitude_masuk,a.akurasi_masuk,a.alamat_masuk,
            a.latitude_pulang,a.longitude_pulang,a.akurasi_pulang,a.alamat_pulang,
            CASE WHEN a.foto_masuk IS NOT NULL THEN 1 ELSE 0 END AS ada_foto_masuk,
            CASE WHEN a.foto_pulang IS NOT NULL THEN 1 ELSE 0 END AS ada_foto_pulang,
            k.kode,k.nama,k.jabatan FROM absensi a JOIN karyawan k ON k.id=a.karyawan_id
            WHERE a.tanggal LIKE ? ORDER BY a.tanggal DESC,a.jam_masuk DESC""",(bulan+'%',)).fetchall()]; conn.close(); return jsonify(rows)
    data=request.get_json(silent=True) or {}
    try:
        akun=pengguna_saat_ini();boleh_lain=bool(akun and (akun.get('is_owner') or str(akun.get('jabatan','')).strip().lower()=='kepala toko' or 'absensi_karyawan_lain' in izin_pengguna(akun)))
        kid=int(data.get('karyawan_id')) if boleh_lain else int(akun.get('karyawan_id') or 0)
        catatan=str(data.get('catatan','')).strip() if boleh_lain else ''
        aksi=data.get('aksi','masuk'); foto,latitude,longitude,akurasi,alamat=baca_bukti_absensi(data); kini=sekarang(); tanggal=kini.strftime('%Y-%m-%d'); jam=kini.strftime('%H:%M:%S')
        k=conn.execute("SELECT * FROM karyawan WHERE id=? AND aktif=1",(kid,)).fetchone()
        if not k: raise ValueError('Karyawan aktif tidak ditemukan.')
        ada=conn.execute("SELECT * FROM absensi WHERE karyawan_id=? AND tanggal=?",(kid,tanggal)).fetchone()
        if aksi=='masuk':
            if ada and ada['jam_masuk']: raise ValueError('Karyawan sudah absen masuk hari ini.')
            if ada: conn.execute("UPDATE absensi SET jam_masuk=?,status='Hadir',catatan=?,foto_masuk=?,latitude_masuk=?,longitude_masuk=?,akurasi_masuk=?,alamat_masuk=? WHERE id=?",(jam,catatan,foto,latitude,longitude,akurasi,alamat,ada['id']))
            else: conn.execute("INSERT INTO absensi(karyawan_id,tanggal,jam_masuk,status,catatan,foto_masuk,latitude_masuk,longitude_masuk,akurasi_masuk,alamat_masuk) VALUES(?,?,?,?,?,?,?,?,?,?)",(kid,tanggal,jam,'Hadir',catatan,foto,latitude,longitude,akurasi,alamat))
        elif aksi=='pulang':
            if not ada or not ada['jam_masuk']: raise ValueError('Silakan absen masuk terlebih dahulu.')
            if ada['jam_pulang']: raise ValueError('Karyawan sudah absen pulang hari ini.')
            conn.execute("UPDATE absensi SET jam_pulang=?,foto_pulang=?,latitude_pulang=?,longitude_pulang=?,akurasi_pulang=?,alamat_pulang=? WHERE id=?",(jam,foto,latitude,longitude,akurasi,alamat,ada['id']))
        else: raise ValueError('Aksi absensi tidak valid.')
        conn.commit(); return jsonify({'status':'sukses','pesan':f"Absensi {aksi} {k['nama']} tercatat pukul {jam} WIB."})
    except (ValueError,TypeError) as e: return jsonify({'status':'error','pesan':str(e)}),400
    finally: conn.close()

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
