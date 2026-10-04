# PEJADIN (prototype)
Cara jalan lokal di VS Code pada Windows (butuh Python 3.10+), dari folder project:

    py -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    .\.venv\Scripts\python.exe -m uvicorn main:app --app-dir backend --reload --host 0.0.0.0 --port 8000

Buka http://localhost:8000. Untuk akses lewat VS Code Ports, teruskan port 8000. Database SQLite dibuat otomatis di `database/pejadin.db` beserta data contoh.
Login demo (password = username + 123): admin, operator, ppk, bendahara, pegawai (contoh: admin / admin123).

- `backend/main.py` API, mesin hitung (P1-P6), validasi V1-V9, alur status, audit, cetak HTML
- `frontend/index.html` antarmuka (satu halaman)
- `design/` acuan desain Stitch
Data pegawai/tarif adalah CONTOH; ganti dengan data klien. Tarif NTB dan Eselon I memakai angka dari contoh dokumen.

## Deploy ke Vercel

Vercel menjalankan aplikasi sebagai function, jadi SQLite lokal tidak bisa dipakai sebagai database permanen. Deploy ini memakai PostgreSQL eksternal (misalnya Supabase) untuk menyimpan akun, surat tugas, dan data referensi.

1. Buat project PostgreSQL di Supabase dan salin connection string **Transaction pooler** dari **Connect**.
2. Di Vercel, buka **Project Settings → Environment Variables**, lalu tambahkan:
   - `DATABASE_URL`: connection string Transaction pooler PostgreSQL.
   - `SECRET`: secret acak panjang untuk tanda tangan sesi (contoh membuatnya: `py -c "import secrets; print(secrets.token_urlsafe(48))"`).
   - `INITIAL_ADMIN_PASSWORD`: password admin awal yang kuat (dipakai hanya saat database masih kosong).
   - `INITIAL_ADMIN_USERNAME`: username admin awal; opsional, default `admin`.
3. Pastikan `vercel.json` berada di root repository dan **Root Directory** Vercel menunjuk ke root repository (satu tingkat di atas folder `pejadin`), environment variables berlaku untuk environment deployment yang dipilih, lalu redeploy. Konfigurasi root tersebut mengarahkan semua path ke service FastAPI `pejadin`.

Saat database PostgreSQL baru pertama kali diinisialisasi, aplikasi membuat skema, data referensi contoh, dan satu akun admin memakai kredensial environment di atas. Pengguna dan database SQLite lokal tidak disalin otomatis ke Supabase. Setelah deployment berhasil, masuk sebagai admin awal lalu buat akun lain melalui menu **Kelola Akun**. Jangan gunakan password demo lokal pada deployment publik.
