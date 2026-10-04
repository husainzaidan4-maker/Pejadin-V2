import sqlite3,json,hmac,hashlib,base64,time,os,io,datetime as dt
from fastapi import FastAPI,Depends,HTTPException,Request
from fastapi.responses import HTMLResponse,StreamingResponse
from fastapi.staticfiles import StaticFiles
D=os.path.dirname(os.path.abspath(__file__))
DB=os.getenv("DB_PATH",os.path.join(D,"..","database","pejadin.db"))
DATABASE_URL=os.getenv("DATABASE_URL")
USE_POSTGRES=bool(DATABASE_URL)
if USE_POSTGRES:
    from psycopg import IntegrityError as DatabaseIntegrityError
else:
    DatabaseIntegrityError=sqlite3.IntegrityError
SECRET=os.getenv("SECRET","ganti-rahasia-ini")
app=FastAPI(title="PEJADIN")
def db():
    if USE_POSTGRES:
        import psycopg
        from psycopg.rows import dict_row
        return psycopg.connect(DATABASE_URL,connect_timeout=10,row_factory=dict_row)
    c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c
def prepare(sql):return sql.replace("?","%s") if USE_POSTGRES else sql
def q(sql,a=(),one=False):
    c=db()
    try:
        r=[dict(x) for x in c.execute(prepare(sql),a).fetchall()]
        c.commit()
    finally:c.close()
    return (r[0] if r else None) if one else r
def ex(sql,a=()):
    c=db()
    try:
        cur=c.execute(prepare(sql),a)
        row=cur.fetchone() if " returning " in sql.lower() else None
        i=row["id"] if row else (cur.lastrowid if not USE_POSTGRES else None)
        c.commit()
        return i
    finally:c.close()
def hp(p):return hashlib.pbkdf2_hmac("sha256",p.encode(),b"pejadin",50000).hex()
def err(code,msg,st=400):raise HTTPException(st,{"error":{"code":code,"message":msg}})
def require_fields(b,fields):
    missing=[k for k in fields if b.get(k) is None or not str(b[k]).strip()]
    if missing:err("422","Kolom wajib diisi: "+", ".join(missing),422)
def sig(b):return hmac.new(SECRET.encode(),b.encode(),hashlib.sha256).hexdigest()
def user(req:Request):
    t=req.headers.get("authorization","")[7:] or req.query_params.get("token","")
    try:
        b,s=t.split(".");assert hmac.compare_digest(s,sig(b))
        d=json.loads(base64.urlsafe_b64decode(b));assert d["exp"]>time.time()
        u=q("select * from users where id=? and aktif=1",(d["id"],),True);assert u
    except Exception:err("401","Sesi tidak valid, silakan login ulang",401)
    return u
def need(*roles):
    def f(u=Depends(user)):
        if u["role"]!="ADMIN" and u["role"] not in roles:err("403","Peran tidak berhak",403)
        return u
    return f
NOW=lambda:dt.datetime.now().isoformat(" ","seconds")
def log(u,aksi,ent,eid,det=""):ex('insert into audit("user",aksi,entitas,eid,detail,at) values(?,?,?,?,?,?)',(u["username"],aksi,ent,eid,det,NOW()))
SCHEMA="""
create table if not exists users(id integer primary key,username text unique,password_hash text,nama text,pegawai_id int,role text,aktif int default 1);
create table if not exists pegawai(id integer primary key,nama text,nip text unique,golongan text,jabatan text,eselon text,unit_kerja text,aktif int default 1);
create table if not exists tarif(id integer primary key,tahun int,provinsi text,harian int,inap1 int,inap2 int,inap3 int,inap4 int,taksi int,unique(tahun,provinsi));
create table if not exists pejabat(id integer primary key,peran text,nama text,nip text,jabatan text,aktif int default 1);
create table if not exists dasar_hukum(id integer primary key,urutan int,teks text,aktif int default 1);
create table if not exists satker(k text primary key,v text);
create table if not exists st(id integer primary key,nomor text,tahun int,maksud text,asal text,tujuan text,provinsi text,tgl_berangkat text,tgl_kembali text,tgl_tiba text,alat text,akun text,jenis text,status text default 'DRAFT',alasan text,dibuat_oleh text,diterbitkan_oleh text);
create table if not exists spd(id integer primary key,st_id int,urutan int,pegawai_id int,nama text,nip text,golongan text,jabatan text,eselon text,hari int,malam int,tarif_inap int,tiket int,lain int,tarif_harian int,uang_harian int,uang_inap int,taksi int,tarif_rep int,rep int,jumlah int,batas int,flag int);
create table if not exists audit(id integer primary key,"user" text,aksi text,entitas text,eid int,detail text,at text);
create unique index if not exists ux_nomor on st(tahun,nomor) where nomor is not null;
"""
PROV="ACEH,SUMATERA UTARA,SUMATERA BARAT,RIAU,JAMBI,SUMATERA SELATAN,BENGKULU,LAMPUNG,KEPULAUAN BANGKA BELITUNG,KEPULAUAN RIAU,DKI JAKARTA,JAWA BARAT,JAWA TENGAH,DI YOGYAKARTA,JAWA TIMUR,BANTEN,BALI,NUSA TENGGARA BARAT,NUSA TENGGARA TIMUR,KALIMANTAN BARAT,KALIMANTAN TENGAH,KALIMANTAN SELATAN,KALIMANTAN TIMUR,KALIMANTAN UTARA,SULAWESI UTARA,SULAWESI TENGAH,SULAWESI SELATAN,SULAWESI TENGGARA,GORONTALO,SULAWESI BARAT,MALUKU,MALUKU UTARA,PAPUA,PAPUA BARAT,PAPUA SELATAN,PAPUA TENGAH,PAPUA PEGUNUNGAN,PAPUA BARAT DAYA".split(",")
@app.on_event("startup")
def init():
    if os.getenv("VERCEL") and not USE_POSTGRES:
        raise RuntimeError("DATABASE_URL must point to a persistent PostgreSQL database on Vercel")
    c=db()
    try:
        if USE_POSTGRES:
            if SECRET=="ganti-rahasia-ini":
                raise RuntimeError("Set a unique SECRET environment variable for PostgreSQL deployments")
            c.execute("select pg_advisory_xact_lock(%s)",(7421962026,))
            schema=SCHEMA.replace("id integer primary key","id integer generated by default as identity primary key")
            for statement in schema.split(";"):
                if statement.strip():c.execute(statement)
            if c.execute("select 1 from users limit 1").fetchone():
                c.commit();return
            admin_password=os.getenv("INITIAL_ADMIN_PASSWORD")
            if not admin_password:
                raise RuntimeError("Set INITIAL_ADMIN_PASSWORD before initializing the PostgreSQL database")
            admin_username=os.getenv("INITIAL_ADMIN_USERNAME","admin")
            users=[(admin_username,"ADMIN",os.getenv("INITIAL_ADMIN_NAME","Administrator"),None,admin_password)]
        else:
            if os.path.exists(DB) and q("select name from sqlite_master where name='users'"):
                return
            c.executescript(SCHEMA)
            users=[(u,r,n,p,u+"123") for u,r,n,p in [("admin","ADMIN","Administrator",None),("operator","OPERATOR","Operator Satker",None),("ppk","PPK","Dedi Adrianto, SE, MM",None),("bendahara","BENDAHARA","Bendahara Pengeluaran",None),("pegawai","PEGAWAI","Pegawai Contoh",1)]]
        for u,r,n,p,password in users:
            execute(c,"insert into users(username,password_hash,nama,role,pegawai_id) values(?,?,?,?,?) on conflict do nothing",(u,hp(password),n,r,p))
        seed_reference_data(c)
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:c.close()

def execute(c,sql,a=()):
    return c.execute(prepare(sql),a)

def seed_reference_data(c):
    for r in [("Arnold A.P. Ritiauw","196903102026211001","IV/d","Sekretaris Direktorat Jenderal","I.a","Sekretariat Ditjen"),("Budi Contoh","197001012000031001","IV/c","Kepala Bagian Umum","II.a","Bagian Umum"),("Siti Rahma","198002022005012002","III/d","Kepala Subbagian","III.a","Bagian Keuangan"),("Andi Wijaya","198505052010011003","III/b","Pelaksana","IV.a","Bagian Umum"),("Dewi Lestari","199001012015022001","III/a","Pelaksana","IV.a","Bagian Program"),("Rudi Hartono","198803032012011004","III/c","Analis Anggaran","III.a","Bagian Keuangan")]:
        execute(c,"insert into pegawai(nama,nip,golongan,jabatan,eselon,unit_kerja) values(?,?,?,?,?,?) on conflict do nothing",r)
    for i,p in enumerate(PROV):
        h,i1=(440000,4682000) if p=="NUSA TENGGARA BARAT" else (370000+(i%6)*30000,3500000+(i%7)*250000)
        execute(c,"insert into tarif(tahun,provinsi,harian,inap1,inap2,inap3,inap4,taksi) values(2026,?,?,?,?,?,?,?) on conflict do nothing",(p,h,i1,int(i1*.75),int(i1*.5),int(i1*.4),150000+(i%4)*50000))
    for r,n in [("PPK","Dedi Adrianto, SE, MM"),("BENDAHARA","Bendahara Pengeluaran"),("SEKDITJEN","Arnold A.P. Ritiauw"),("KABAG","Budi Contoh"),("PELAKSANA_ADM","Siti Rahma"),("PEMBUAT_DAFTAR","Andi Wijaya"),("PENGESAH","Arnold A.P. Ritiauw")]:
        execute(c,"insert into pejabat(peran,nama,nip,jabatan) values(?,?,?,?) on conflict do nothing",(r,n,"000000000000000000",r.title()))
    for i,t in enumerate(["Peraturan Menteri Keuangan Nomor 113/PMK.05/2012 tentang Perjalanan Dinas Dalam Negeri","Peraturan Menteri Keuangan Nomor 32 Tahun 2025 tentang Standar Biaya Masukan TA 2026","DIPA Satuan Kerja Tahun Anggaran 2026"]):
        execute(c,"insert into dasar_hukum(urutan,teks) values(?,?) on conflict do nothing",(i+1,t))
    for k,v in {"nama_kementerian":"KEMENTERIAN PEKERJAAN UMUM","nama_ditjen":"DIREKTORAT JENDERAL SUMBER DAYA AIR","nama_satker":"Sekretariat Direktorat Jenderal Sumber Daya Air","alamat":"Jakarta","kode_satker":"694257","nomor_dipa":"","akun_default":"7755.EBA.962.182.524111 D","nomor_sptjb":"","kota":"Jakarta"}.items():
        execute(c,"insert into satker values(?,?) on conflict do nothing",(k,v))
@app.post("/api/login")
async def login(r:Request):
    b=await r.json();u=q("select * from users where username=? and aktif=1",(b.get("username"),),True)
    if not u or u["password_hash"]!=hp(b.get("password","")):err("401","Username atau password salah",401)
    t=base64.urlsafe_b64encode(json.dumps({"id":u["id"],"exp":time.time()+28800}).encode()).decode()
    log(u,"LOGIN","users",u["id"]);u.pop("password_hash");return {"token":t+"."+sig(t),"user":u}
@app.get("/api/me")
def me(u=Depends(user)):u.pop("password_hash");return u
T={"pegawai":("pegawai","nama nip golongan jabatan eselon unit_kerja aktif"),"tarif":("tarif","tahun provinsi harian inap1 inap2 inap3 inap4 taksi"),"pejabat":("pejabat","peran nama nip jabatan aktif"),"dasar_hukum":("dasar_hukum","urutan teks aktif"),"users":("users","username nama role pegawai_id aktif")}
REQUIRED_REF_FIELDS={"pegawai":"nama nip golongan jabatan eselon unit_kerja","tarif":"tahun provinsi harian inap1 inap2 inap3 inap4 taksi","pejabat":"peran nama nip jabatan","dasar_hukum":"urutan teks","users":"username password nama role"}
NUMERIC_REF_FIELDS={"tarif":"tahun harian inap1 inap2 inap3 inap4 taksi","dasar_hukum":"urutan"}
@app.get("/api/ref/satker")
def gs(u=Depends(user)):return {r["k"]:r["v"] for r in q("select * from satker")}
@app.put("/api/ref/satker")
async def ps(r:Request,u=Depends(need())):
    b=await r.json()
    if not isinstance(b,dict):err("422","Data satker harus berupa objek",422)
    if not b:err("422","Tidak ada data satker untuk disimpan",422)
    for k,v in b.items():ex("insert into satker values(?,?) on conflict(k) do update set v=excluded.v",(k,str(v)))
    log(u,"UPDATE","satker",0);return {"ok":1}
@app.get("/api/ref/{n}")
def lst(n:str,u=Depends(user)):
    if n not in T:err("404","Tidak ada",404)
    if n=="users" and u["role"]!="ADMIN":err("403","Hanya Admin",403)
    return q(f"select id,{T[n][1].replace(' ',',')} from {T[n][0]} order by "+("tahun desc,provinsi" if n=="tarif" else "id"))
@app.post("/api/ref/{n}")
async def add(n:str,r:Request,u=Depends(need())):
    if n not in T:err("404","Tidak ada",404)
    b=await r.json()
    if not isinstance(b,dict):err("422","Data referensi harus berupa objek",422)
    t,cs=T[n];cs=cs.split();b={k:v for k,v in b.items() if k in cs or k=="password"}
    require_fields(b,REQUIRED_REF_FIELDS[n].split())
    for k in NUMERIC_REF_FIELDS.get(n,"").split():
        try:b[k]=int(b[k])
        except (TypeError,ValueError):err("422",f"{k} harus berupa bilangan bulat",422)
        if b[k]<0 or (k=="tahun" and b[k]==0):err("422",f"{k} tidak boleh bernilai negatif atau nol",422)
    if n=="users" and b["role"] not in ("ADMIN","OPERATOR","PPK","BENDAHARA","PEGAWAI"):err("422","Role tidak dikenal",422)
    if n=="users":b["password_hash"]=hp(b.pop("password"))
    columns=list(b)
    sql=f"insert into {t}({','.join(columns)}) values({','.join('?'*len(columns))})"
    if n=="tarif":
        updates=",".join(f"{k}=excluded.{k}" for k in columns if k not in ("tahun","provinsi"))
        sql+=f" on conflict(tahun,provinsi) do update set {updates}"
    sql+=" returning id"
    try:i=ex(sql,list(b.values()))
    except DatabaseIntegrityError as e:err("409","Data duplikat: "+str(e),409)
    log(u,"CREATE",n,i,json.dumps(b)[:200]);return {"id":i}
@app.put("/api/ref/{n}/{i}")
async def upd(n:str,i:int,r:Request,u=Depends(need())):
    if n not in T:err("404","Tidak ada",404)
    b=await r.json()
    if not isinstance(b,dict):err("422","Data referensi harus berupa objek",422)
    t,cs=T[n];b={k:v for k,v in b.items() if k in cs.split()}
    if not b:err("422","Tidak ada data referensi untuk diperbarui",422)
    ex(f"update {t} set "+",".join(f"{k}=?" for k in b)+" where id=?",list(b.values())+[i]);log(u,"UPDATE",n,i,json.dumps(b)[:200]);return {"ok":1}
def rep_of(e):return 200000 if e.startswith("I.") else 150000 if e.startswith("II.") else 0
def hitung(s,pg,hari,malam,tinap,tiket,lain):
    if not pg["eselon"] or not pg["golongan"]:err("V7",f"Eselon & golongan '{pg['nama']}' belum terisi")
    if malam>max(hari-1,0):err("V4",f"malam inap ({malam}) untuk '{pg['nama']}' melebihi hari-1 ({hari-1})")
    if malam>0 and not tinap:err("V4",f"malam inap > 0 untuk '{pg['nama']}' tetapi tarif_inap (bill hotel) belum diisi")
    t=q("select * from tarif where tahun=? and provinsi=?",(int(s["tgl_berangkat"][:4]),s["provinsi"]),True)
    if not t:err("V3",f"Tarif {s['provinsi']} tahun {s['tgl_berangkat'][:4]} belum tersedia")
    e=pg["eselon"];rp_=rep_of(e);tx=0 if rp_ else t["taksi"]
    bt=t["inap1"] if e.startswith("I.") else t["inap2"] if e.startswith("II.") else t["inap3"] if e.startswith("III.") else t["inap4"]
    uh=hari*t["harian"];ui=malam*tinap
    return dict(tarif_harian=t["harian"],uang_harian=uh,uang_inap=ui,taksi=tx,tarif_rep=rp_,rep=hari*rp_,jumlah=uh+ui+tiket+tx+lain+hari*rp_,batas=bt,flag=int(tinap>bt))
def lama(s):return (dt.date.fromisoformat(s["tgl_kembali"])-dt.date.fromisoformat(s["tgl_berangkat"])).days+1
@app.get("/api/st")
def stl(status:str="",cari:str="",u=Depends(user)):
    w,a=["1=1"],[]
    if status:w.append("s.status=?");a.append(status)
    if cari:w.append("(s.nomor like ? or s.maksud like ? or s.tujuan like ?)");a+=[f"%{cari}%"]*3
    if u["role"]=="PEGAWAI":w.append("exists(select 1 from spd where st_id=s.id and pegawai_id=?)");a.append(u["pegawai_id"])
    return q("select s.*,(select count(*) from spd where st_id=s.id) jml,coalesce((select sum(jumlah) from spd where st_id=s.id),0) total,coalesce((select max(flag) from spd where st_id=s.id),0) flag from st s where "+" and ".join(w)+" order by s.id desc",a)
@app.post("/api/st")
async def stc(r:Request,u=Depends(need("OPERATOR"))):
    b=await r.json()
    if not isinstance(b,dict):err("422","Data surat tugas harus berupa objek",422)
    require_fields(b,"maksud asal tujuan provinsi tgl_berangkat tgl_kembali alat akun jenis".split())
    try:
        berangkat=dt.date.fromisoformat(b["tgl_berangkat"])
        kembali=dt.date.fromisoformat(b["tgl_kembali"])
    except (TypeError,ValueError):err("422","Format tanggal wajib YYYY-MM-DD",422)
    if kembali<berangkat:err("V1","Tanggal kembali tidak boleh sebelum tanggal berangkat")
    if b["jenis"] not in ("UP","LS"):err("422","Jenis kuitansi harus UP atau LS",422)
    if not q("select 1 from tarif where provinsi=?",(b.get("provinsi"),)):err("V2","Provinsi tarif wajib dipilih dari daftar")
    if not q("select 1 from tarif where tahun=? and provinsi=?",(berangkat.year,b["provinsi"])):err("V3",f"Tarif {b['provinsi']} tahun {berangkat.year} belum tersedia")
    k="maksud asal tujuan provinsi tgl_berangkat tgl_kembali alat akun jenis".split();v=[b.get(x) for x in k]
    i=ex(f"insert into st({','.join(k)},tahun,dibuat_oleh) values({','.join('?'*(len(k)+2))}) returning id",v+[berangkat.year,u["username"]]);log(u,"CREATE","st",i);return {"id":i,"status":"DRAFT"}
@app.get("/api/st/{i}")
def std(i:int,u=Depends(user)):
    s=q("select * from st where id=?",(i,),True)
    if not s:err("404","Tidak ditemukan",404)
    s["spd"]=q("select * from spd where st_id=? order by urutan",(i,));s["lama"]=lama(s);s["total"]=sum(x["jumlah"] for x in s["spd"]);return s
@app.delete("/api/st/{i}")
def stx(i:int,u=Depends(need("OPERATOR"))):
    if std(i,u)["status"]!="DRAFT":err("409","Hanya Draft yang bisa dihapus",409)
    ex("delete from spd where st_id=?",(i,));ex("delete from st where id=?",(i,));log(u,"DELETE","st",i);return {"ok":1}
@app.post("/api/st/{i}/spd")
async def spa(i:int,r:Request,u=Depends(need("OPERATOR"))):
    s=std(i,u);b=await r.json()
    if s["status"]!="DRAFT":err("409","Hanya Draft yang bisa diubah",409)
    pg=q("select * from pegawai where id=? and aktif=1",(b.get("pegawai_id"),),True)
    if not pg:err("404","Pegawai tidak ditemukan",404)
    if any(x["pegawai_id"]==pg["id"] for x in s["spd"]):err("409","Pegawai sudah ada di surat tugas ini",409)
    o=q("select s.id from spd p join st s on s.id=p.st_id where p.pegawai_id=? and s.id!=? and s.status!='DIBATALKAN' and s.tgl_berangkat<=? and s.tgl_kembali>=?",(pg["id"],i,s["tgl_kembali"],s["tgl_berangkat"]))
    if o:err("V5",f"'{pg['nama']}' sudah punya perjalanan lain di tanggal yang bertumpuk (ST #{o[0]['id']})")
    def n(k):
        try:v=int(b.get(k) or 0)
        except (TypeError,ValueError):err("422",f"{k} harus berupa bilangan bulat",422)
        if v<0:err("422",f"{k} tidak boleh negatif",422)
        return v
    hari=n("hari") or s["lama"]
    h=hitung(s,pg,hari,n("malam"),n("tarif_inap"),n("tiket"),n("lain"))
    d=dict(st_id=i,urutan=len(s["spd"])+1,pegawai_id=pg["id"],nama=pg["nama"],nip=pg["nip"],golongan=pg["golongan"],jabatan=pg["jabatan"],eselon=pg["eselon"],hari=hari,malam=n("malam"),tarif_inap=n("tarif_inap"),tiket=n("tiket"),lain=n("lain"),**h)
    d["id"]=ex(f"insert into spd({','.join(d)}) values({','.join('?'*len(d))}) returning id",list(d.values()));log(u,"CREATE","spd",d["id"]);return d
@app.delete("/api/st/{i}/spd/{p}")
def spx(i:int,p:int,u=Depends(need("OPERATOR"))):
    if std(i,u)["status"]!="DRAFT":err("409","Hanya Draft yang bisa diubah",409)
    ex("delete from spd where id=? and st_id=?",(p,i));return {"ok":1}
@app.post("/api/st/{i}/{act}")
async def aksi(i:int,act:str,r:Request,u=Depends(user)):
    raw=await r.body();b=json.loads(raw) if raw else {};s=std(i,u);st=s["status"]
    M={"ajukan":("OPERATOR","DRAFT","DIAJUKAN"),"kembalikan":("PPK","DIAJUKAN","DRAFT"),"terbitkan":("PPK","DIAJUKAN","TERBIT"),"selesaikan":("OPERATOR","TERBIT","SELESAI"),"batalkan":("PPK",None,"DIBATALKAN")}
    if act not in M:err("404","Aksi tidak dikenal",404)
    rl,fr,to=M[act]
    if u["role"] not in("ADMIN",rl) and not(act=="selesaikan" and u["role"]=="PPK"):err("403","Peran tidak berhak",403)
    if (fr and st!=fr) or st in("SELESAI","DIBATALKAN"):err("409",f"Status {st} tidak bisa {act}",409)
    if act=="ajukan" and not s["spd"]:err("422","Tambahkan minimal 1 pelaksana")
    if act in("kembalikan","batalkan") and not b.get("alasan"):err("422","Alasan wajib diisi")
    if act=="terbitkan":
        nm=(b.get("nomor") or "").strip()
        if not nm:err("422","Nomor surat tugas wajib diisi")
        if q("select 1 from st where nomor=? and tahun=? and id!=?",(nm,s["tahun"],i)):err("V6",f"Nomor Surat Tugas '{nm}' sudah dipakai.")
        for p in s["spd"]:hitung(s,q("select * from pegawai where id=?",(p["pegawai_id"],),True),p["hari"],p["malam"],p["tarif_inap"],p["tiket"],p["lain"])
        ex("update st set nomor=?,diterbitkan_oleh=? where id=?",(nm,u["nama"],i))
    if act=="selesaikan":ex("update st set tgl_tiba=? where id=?",(b.get("tgl_tiba") or s["tgl_kembali"],i))
    ex("update st set status=?,alasan=? where id=?",(to,b.get("alasan"),i));log(u,act.upper(),"st",i,b.get("alasan") or b.get("nomor") or "");return {"id":i,"status":to}
@app.get("/api/audit")
def aud(u=Depends(need())):return q("select * from audit order by id desc limit 300")
def rp(n):return "Rp"+f"{n:,}".replace(",",".")
def tb(n):
    s=["","satu","dua","tiga","empat","lima","enam","tujuh","delapan","sembilan","sepuluh","sebelas"];j=lambda x:(" "+tb(x)) if x else ""
    if n<12:return s[n]
    if n<20:return tb(n-10)+" belas"
    if n<100:return tb(n//10)+" puluh"+j(n%10)
    if n<200:return "seratus"+j(n-100)
    if n<1000:return tb(n//100)+" ratus"+j(n%100)
    if n<2000:return "seribu"+j(n-1000)
    if n<10**6:return tb(n//1000)+" ribu"+j(n%1000)
    if n<10**9:return tb(n//10**6)+" juta"+j(n%10**6)
    return tb(n//10**9)+" miliar"+j(n%10**9)
@app.get("/api/doc/{i}/{jenis}",response_class=HTMLResponse)
def doc(i:int,jenis:str,u=Depends(user)):
    s=std(i,u);S=gs(u);pj={p["peran"]:p for p in q("select * from pejabat where aktif=1")}
    if s["status"] not in("TERBIT","SELESAI"):err("V8","Dokumen hanya bisa dicetak bila status TERBIT/SELESAI",403)
    if u["role"]=="PEGAWAI":
        s["spd"]=[x for x in s["spd"] if x["pegawai_id"]==u["pegawai_id"]]
        if not s["spd"]:err("403","Bukan SPD Anda",403)
    log(u,"CETAK","st",i,jenis)
    kop=f"<div style='text-align:center'><b>{S['nama_kementerian']}<br>{S['nama_ditjen']}</b><br>{S['nama_satker']}<br><small>{S['alamat']}</small><hr></div>"
    ttd=lambda r:f"<div style='float:right;text-align:center;margin-top:30px'>{S['kota']}, {s['tgl_berangkat']}<br>{pj[r]['jabatan']}<br><br><br><br><u>{pj[r]['nama']}</u><br>NIP {pj[r]['nip']}</div><div style='clear:both'></div>" if r in pj else ""
    ident=f"<p>Nomor: <b>{s['nomor']}</b><br>Maksud: {s['maksud']}<br>Tujuan: {s['tujuan']} ({s['provinsi']})<br>Tanggal: {s['tgl_berangkat']} s/d {s['tgl_kembali']} ({s['lama']} hari)</p>"
    tbl=lambda rows,h:"<table border=1 cellpadding=5 style='border-collapse:collapse;width:100%'><tr>"+"".join(f"<th>{x}</th>" for x in h)+"</tr>"+"".join("<tr>"+"".join(f"<td>{c}</td>" for c in r)+"</tr>" for r in rows)+"</table>"
    sp=s["spd"];tot=sum(x["jumlah"] for x in sp)
    if jenis=="st":b=f"<h3 align=center>SURAT TUGAS<br><small>Nomor: {s['nomor']}</small></h3><p>Dasar:</p><ol>"+"".join(f"<li>{d['teks']}</li>" for d in q("select * from dasar_hukum where aktif=1 order by urutan"))+"</ol><p>Menugaskan:</p>"+tbl([(x["urutan"],x["nama"],x["nip"],x["jabatan"]) for x in sp],["No","Nama","NIP","Jabatan"])+f"<p>Untuk {s['maksud']} di {s['tujuan']} pada {s['tgl_berangkat']} s/d {s['tgl_kembali']}.</p>"+ttd("SEKDITJEN")
    elif jenis=="spd":b="".join(f"<div style='page-break-after:always'><h3 align=center>SURAT PERJALANAN DINAS (SPD)</h3>{ident}<p>Pelaksana: <b>{x['nama']}</b> / {x['nip']} / {x['golongan']} / {x['jabatan']}<br>Alat angkut: {s['alat']}<br>Akun: {s['akun']}</p>{ttd('PPK')}</div>" for x in sp)
    elif jenis=="rincian":b="".join(f"<div style='page-break-after:always'><h3 align=center>RINCIAN BIAYA PERJALANAN DINAS</h3>{ident}<p>{x['nama']}</p>"+tbl([("Uang harian",f"{x['hari']} x {rp(x['tarif_harian'])}",rp(x['uang_harian'])),("Penginapan (at-cost)",f"{x['malam']} x {rp(x['tarif_inap'])}",rp(x['uang_inap'])),("Transport/tiket","",rp(x['tiket'])),("Taksi","",rp(x['taksi'])),("Representasi",f"{x['hari']} x {rp(x['tarif_rep'])}",rp(x['rep'])),("Biaya lain","",rp(x['lain'])),("<b>Jumlah</b>","",f"<b>{rp(x['jumlah'])}</b>")],["Uraian","Perhitungan","Jumlah"])+f"<p><i>Terbilang: {tb(x['jumlah'])} rupiah</i></p>{ttd('PPK')}</div>" for x in sp)
    elif jenis=="kuitansi":b=f"<h3 align=center>KUITANSI ({s['jenis']})</h3>{ident}<p>Telah terima sejumlah <b>{rp(tot)}</b><br><i>Terbilang: {tb(tot)} rupiah</i><br>Untuk pembayaran perjalanan dinas {s['maksud']}</p>{ttd('BENDAHARA')}"
    elif jenis=="nominatif":b="<h3 align=center>DAFTAR NOMINATIF</h3>"+ident+tbl([(x["urutan"],x["nama"],rp(x["uang_harian"]),rp(x["uang_inap"]),rp(x["tiket"]),rp(x["taksi"]+x["lain"]+x["rep"]),rp(x["jumlah"])) for x in sp],["No","Nama","Harian","Inap","Tiket","Lain+Rep","Jumlah"])+f"<p><b>Total: {rp(tot)}</b></p>"+ttd("PEMBUAT_DAFTAR")
    else:err("404","Jenis dokumen tidak ada",404)
    return f"<html><body style='font-family:serif;max-width:800px;margin:auto'>{kop}{b}<script>print()</script></body></html>"
@app.get("/api/laporan")
def lap(format:str="xlsx",tahun:int=0,status:str="",u=Depends(need("OPERATOR","PPK","BENDAHARA"))):
    rows=[r for r in stl(status,"",u) if not tahun or r["tahun"]==tahun];H=["No ST","Tujuan","Berangkat","Kembali","Pelaksana","Total Biaya","Status"]
    R=[(r["nomor"] or "-",r["tujuan"],r["tgl_berangkat"],r["tgl_kembali"],r["jml"],r["total"],r["status"]) for r in rows]
    if format=="pdf":return HTMLResponse("<html><body style='font-family:sans-serif'><h3>Rekap Surat Tugas</h3><table border=1 cellpadding=4 style='border-collapse:collapse'><tr>"+"".join(f"<th>{h}</th>" for h in H)+"</tr>"+"".join("<tr>"+"".join(f"<td>{c}</td>" for c in r)+"</tr>" for r in R)+"</table><script>print()</script></body></html>")
    from openpyxl import Workbook
    w=Workbook();a=w.active;a.append(H);[a.append(r) for r in R];o=io.BytesIO();w.save(o);o.seek(0)
    return StreamingResponse(o,media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",headers={"Content-Disposition":"attachment; filename=rekap_surat_tugas.xlsx"})
app.mount("/",StaticFiles(directory=os.path.join(D,"..","frontend"),html=True))
