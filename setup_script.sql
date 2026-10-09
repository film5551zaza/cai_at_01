-- ==========================================
-- 1. เคลียร์ข้อมูลเดิม (ถ้ามี)
-- ==========================================
DROP VIEW IF EXISTS results_view;
DROP TABLE IF EXISTS materials CASCADE;
DROP TABLE IF EXISTS submissions CASCADE;
DROP TABLE IF EXISTS progress CASCADE;
DROP TABLE IF EXISTS attempts CASCADE;
DROP TABLE IF EXISTS students CASCADE;
DROP TABLE IF EXISTS teachers CASCADE;

-- ==========================================
-- 2. สร้างตารางหลัก
-- ==========================================

-- ตารางผู้สอน
CREATE TABLE teachers (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ตารางรายชื่อนักเรียน (อัปโหลดทาง CSV ตอนเริ่มต้น)
CREATE TABLE students (
    id VARCHAR(11) PRIMARY KEY, -- รหัสนักศึกษา 11 หลัก
    title TEXT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    section TEXT,
    user_id UUID UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL, -- ผูกกับ auth เมื่อสมัคร
    photo_path TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ตารางการทำแบบทดสอบ (ก่อน/หลังเรียน)
CREATE TABLE attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    kind TEXT CHECK (kind IN ('pre', 'post')),
    score INTEGER NOT NULL,
    answers JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, kind) -- ทำได้ครั้งเดียว
);

-- ตารางความก้าวหน้า (บทเรียน 1-5)
CREATE TABLE progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    unit INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 5),
    done BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, unit)
);

-- ตารางส่งงานปฏิบัติ AR
CREATE TABLE submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    unit INTEGER NOT NULL DEFAULT 4,
    kind TEXT CHECK (kind IN ('link', 'file')),
    url TEXT,
    storage_path TEXT,
    note TEXT,
    score INTEGER NULL,
    teacher_comment TEXT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ตารางสื่อเสริมของผู้สอน
CREATE TABLE materials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    kind TEXT CHECK (kind IN ('file', 'link', 'video')),
    url TEXT,
    storage_path TEXT,
    file_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    teacher_id UUID REFERENCES auth.users(id) ON DELETE SET NULL
);

-- ==========================================
-- 3. ฟังก์ชันและทริกเกอร์ (Security & Auth)
-- ==========================================

-- ตรวจสอบว่าเป็นผู้สอนหรือไม่ (Security Definer)
CREATE OR REPLACE FUNCTION is_teacher() RETURNS BOOLEAN
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
    SELECT EXISTS (SELECT 1 FROM teachers WHERE user_id = auth.uid());
$$;

-- ฟังก์ชันตรวจสอบก่อนสมัครสมาชิกนักเรียน
CREATE OR REPLACE FUNCTION check_student_registration() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    student_id_val VARCHAR(11);
BEGIN
    -- หากเป็นผู้สอน (อีเมลไม่เป็นตัวเลข 11 หลัก) ให้ข้ามไป
    IF NEW.email NOT SIMILAR TO '[0-9]{11}@%' THEN
        RETURN NEW;
    END IF;

    -- สกัดรหัสนักศึกษาจากอีเมล
    student_id_val := split_part(NEW.email, '@', 1);

    -- ตรวจสอบว่ามีในรายชื่อหรือไม่ และยังไม่ถูกใช้
    IF NOT EXISTS (SELECT 1 FROM students WHERE id = student_id_val) THEN
        RAISE EXCEPTION 'ไม่พบรหัสนักศึกษานี้ในระบบ';
    END IF;
    
    IF EXISTS (SELECT 1 FROM students WHERE id = student_id_val AND user_id IS NOT NULL) THEN
        RAISE EXCEPTION 'รหัสนักศึกษานี้ถูกลงทะเบียนไปแล้ว';
    END IF;

    -- อัปเดตตาราง students เพื่อผูก user_id
    UPDATE students SET user_id = NEW.id WHERE id = student_id_val;

    RETURN NEW;
END;
$$;

-- สร้าง Trigger ผูกกับ auth.users
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION check_student_registration();

-- ==========================================
-- 4. การตั้งค่าความปลอดภัย (Row Level Security)
-- ==========================================
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE materials ENABLE ROW LEVEL SECURITY;

-- ยกเลิกสิทธิ์ทั้งหมดจากผู้ที่ไม่ได้ล็อกอิน
REVOKE ALL ON teachers, students, attempts, progress, submissions, materials FROM anon;

-- นโยบายสำหรับ Teachers (ผู้สอนเห็นทั้งหมด)
CREATE POLICY "Teacher full access students" ON students FOR ALL TO authenticated USING (is_teacher());
CREATE POLICY "Teacher full access attempts" ON attempts FOR ALL TO authenticated USING (is_teacher());
CREATE POLICY "Teacher full access progress" ON progress FOR ALL TO authenticated USING (is_teacher());
CREATE POLICY "Teacher full access materials" ON materials FOR ALL TO authenticated USING (is_teacher());
CREATE POLICY "Teacher full access submissions" ON submissions FOR ALL TO authenticated USING (is_teacher());

-- นโยบายสำหรับ Students (นักเรียนจัดการเฉพาะของตนเอง)
-- Students: ดูข้อมูลตัวเองได้เท่านั้น
CREATE POLICY "Student view own record" ON students FOR SELECT TO authenticated USING (user_id = auth.uid());
-- Students: แก้ไขได้เฉพาะรูปถ่าย (ด้วยหลักการอัปเดต ถ้าเป็นการแก้ฟิลด์อื่น ข้อมูลต้องเหมือนเดิม)
CREATE POLICY "Student update own photo" ON students FOR UPDATE TO authenticated 
USING (user_id = auth.uid())
WITH CHECK (
    user_id = auth.uid() AND 
    id = id AND title = title AND first_name = first_name AND last_name = last_name AND section = section
);

-- Attempts: เพิ่มและดูของตัวเอง
CREATE POLICY "Student view own attempts" ON attempts FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student insert own attempts" ON attempts FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());

-- Progress: เพิ่มและดูของตัวเอง
CREATE POLICY "Student view own progress" ON progress FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student insert own progress" ON progress FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());

-- Materials: นักเรียนดูได้อย่างเดียว
CREATE POLICY "Student view materials" ON materials FOR SELECT TO authenticated USING (NOT is_teacher());

-- Submissions: เพิ่ม, ดู และอัปเดต(ยกเว้นคะแนน) ของตัวเอง
CREATE POLICY "Student view own sub" ON submissions FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student insert own sub" ON submissions FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());
CREATE POLICY "Student update own sub" ON submissions FOR UPDATE TO authenticated 
USING (user_id = auth.uid())
WITH CHECK (
    user_id = auth.uid() AND
    score IS NOT DISTINCT FROM (SELECT score FROM submissions WHERE id = id) AND
    teacher_comment IS NOT DISTINCT FROM (SELECT teacher_comment FROM submissions WHERE id = id)
);

-- ==========================================
-- 5. Storage Buckets และ RLS
-- ==========================================

-- สร้าง Buckets (ต้องใช้ query เพราะไม่มี extension พิเศษ แต่ใน Supabase ทำได้ผ่าน API. 
-- โค้ดล่างนี้เป็นการจำลองการ INSERT ลงตารางหลักของ Storage ภายใน Supabase)
INSERT INTO storage.buckets (id, name, public) VALUES 
('photos', 'photos', false),
('submissions', 'submissions', false),
('materials', 'materials', false)
ON CONFLICT (id) DO NOTHING;

-- RLS ของ Storage Objects
ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;

-- 5.1 Photos: นักเรียนจัดการได้เฉพาะโฟลเดอร์ uid ของตน, รูป <= 2MB
CREATE POLICY "Photos - Students manage own folder" ON storage.objects FOR ALL TO authenticated
USING (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text)
WITH CHECK (
    bucket_id = 'photos' 
    AND (storage.foldername(name))[1] = auth.uid()::text
    AND COALESCE((metadata->>'size')::int, 0) <= 2097152
    AND LOWER(storage.extension(name)) IN ('jpg', 'jpeg', 'png')
);
CREATE POLICY "Photos - Teacher read all" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'photos' AND is_teacher());

-- 5.2 Submissions: งานปฏิบัติ <= 20MB
CREATE POLICY "Subs - Students manage own" ON storage.objects FOR ALL TO authenticated
USING (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text)
WITH CHECK (
    bucket_id = 'submissions' 
    AND (storage.foldername(name))[1] = auth.uid()::text
    AND COALESCE((metadata->>'size')::int, 0) <= 20971520
    AND LOWER(storage.extension(name)) IN ('jpg', 'jpeg', 'png', 'pdf', 'mp4')
);
CREATE POLICY "Subs - Teacher read all" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'submissions' AND is_teacher());

-- 5.3 Materials: ผู้สอนจัดการได้, ทุกคนอ่านได้, สื่อ <= 50MB
CREATE POLICY "Mats - Read all auth" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'materials');
CREATE POLICY "Mats - Teacher manage" ON storage.objects FOR ALL TO authenticated
USING (bucket_id = 'materials' AND is_teacher())
WITH CHECK (
    bucket_id = 'materials' AND is_teacher()
    AND COALESCE((metadata->>'size')::int, 0) <= 52428800
    AND LOWER(storage.extension(name)) IN ('pdf', 'pptx', 'docx')
);

-- ==========================================
-- 6. Views สำหรับแสดงผล
-- ==========================================
-- มุมมองสำหรับผู้สอน ให้ใช้สิทธิ์ผู้เรียก (Security Invoker)
CREATE OR REPLACE VIEW results_view WITH (security_invoker = true) AS
SELECT 
    s.id AS student_id,
    s.title, s.first_name, s.last_name, s.section, s.photo_path,
    (SELECT score FROM attempts a WHERE a.user_id = s.user_id AND kind = 'pre' LIMIT 1) as pre_score,
    (SELECT score FROM attempts a WHERE a.user_id = s.user_id AND kind = 'post' LIMIT 1) as post_score,
    (SELECT COUNT(*) FROM progress p WHERE p.user_id = s.user_id) as units_completed,
    sub.id as submission_id,
    sub.score as submission_score
FROM students s
LEFT JOIN submissions sub ON s.user_id = sub.user_id;

-- ==========================================
-- 7. ข้อมูลจำลอง (Mock Data)
-- ==========================================
-- ข้อมูลนักเรียน 6 คน (วิธีใส่ข้อมูลจริง: ใช้ CSV ผ่าน Supabase Table Editor แทรกที่ตาราง students)
INSERT INTO students (id, title, first_name, last_name, section) VALUES
('11111111101', 'นาย', 'สมชาย', 'ใจดี', '5/1'),
('11111111102', 'นางสาว', 'สมหญิง', 'รักเรียน', '5/1'),
('11111111103', 'นาย', 'มานะ', 'อดทน', '5/2'),
('11111111104', 'นางสาว', 'มานี', 'มีสติ', '5/2'),
('11111111105', 'นาย', 'ปิติ', 'ยินดี', '5/3'),
('11111111106', 'นางสาว', 'ชูใจ', 'ร่าเริง', '5/3')
ON CONFLICT (id) DO NOTHING;

-- ==========================================
-- 8. คำสั่งตั้งค่าผู้สอน (เอาคอมเมนต์ออกเมื่อใช้งานจริง)
-- ==========================================
-- INSERT INTO teachers (user_id, email) 
-- SELECT id, email FROM auth.users WHERE email = 'teacher@khoknongna.ac.th';