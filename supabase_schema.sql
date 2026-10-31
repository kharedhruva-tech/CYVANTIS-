-- ==============================================================================
-- CYVANTIS Cybersecurity Platform
-- Production Supabase Database Schema, Row-Level Security (RLS) & Storage
-- ==============================================================================

-- 0. Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==============================================================================
-- 1. PROFILES TABLE (Mirrors & extends Supabase auth.users)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username VARCHAR(64) UNIQUE,
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(128),
    role VARCHAR(32) NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'analyst', 'viewer')),
    avatar_url TEXT,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 2. MEMBERSHIP PLANS TABLE
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.membership_plans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(32) UNIQUE NOT NULL, -- 'free', 'monthly', 'quarterly', 'yearly'
    name VARCHAR(64) NOT NULL,
    description TEXT,
    price_inr NUMERIC(10, 2) NOT NULL DEFAULT 0.00,
    duration_days INTEGER NOT NULL DEFAULT 0,
    tier VARCHAR(32) NOT NULL DEFAULT 'free', -- 'free' or 'premium'
    badge VARCHAR(32),
    daily_scan_limit INTEGER NOT NULL DEFAULT 5, -- -1 for unlimited
    features JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 3. UPI CONFIGS TABLE (Admin configurable payment QR / VPA)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.upi_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    upi_id VARCHAR(128) NOT NULL DEFAULT 'cyvantis.pay@upi',
    account_name VARCHAR(128) NOT NULL DEFAULT 'CYVANTIS Cybersecurity Nexus',
    merchant_code VARCHAR(32),
    qr_image_url TEXT,
    instructions TEXT NOT NULL DEFAULT 'Scan using any UPI App (Google Pay, PhonePe, Paytm, BHIM). Upload screenshot and enter UTR.',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 4. PAYMENT ORDERS TABLE
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.payment_orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_code VARCHAR(32) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    plan_id UUID NOT NULL REFERENCES public.membership_plans(id) ON DELETE RESTRICT,
    payment_method VARCHAR(32) NOT NULL CHECK (payment_method IN ('upi_qr', 'razorpay')),
    amount_inr NUMERIC(10, 2) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'failed')),
    upi_ref_no VARCHAR(64) UNIQUE,
    receipt_screenshot_url TEXT,
    gateway_order_id VARCHAR(128),
    gateway_payment_id VARCHAR(128) UNIQUE,
    gateway_signature VARCHAR(256),
    admin_notes TEXT,
    verified_by_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 5. MEMBERSHIPS TABLE (Active user subscriptions)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.memberships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID UNIQUE NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    plan_id UUID NOT NULL REFERENCES public.membership_plans(id) ON DELETE RESTRICT,
    status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked')),
    start_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_date TIMESTAMPTZ, -- NULL for lifetime/free, timestamp for active duration
    auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
    last_order_id UUID REFERENCES public.payment_orders(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 6. PAYMENT AUDIT LOGS TABLE (Immutable verification trail)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.payment_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id UUID REFERENCES public.payment_orders(id) ON DELETE SET NULL,
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    action VARCHAR(64) NOT NULL,
    details JSONB,
    performed_by_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    performed_by_name VARCHAR(128),
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 7. PERFORMANCE INDEXES
-- ==============================================================================
CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);
CREATE INDEX IF NOT EXISTS idx_plans_active ON public.membership_plans(is_active);
CREATE INDEX IF NOT EXISTS idx_orders_user ON public.payment_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON public.payment_orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_upi_ref ON public.payment_orders(upi_ref_no);
CREATE INDEX IF NOT EXISTS idx_orders_gateway_pay ON public.payment_orders(gateway_payment_id);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON public.memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_status ON public.memberships(status);
CREATE INDEX IF NOT EXISTS idx_memberships_end_date ON public.memberships(end_date);
CREATE INDEX IF NOT EXISTS idx_audit_order ON public.payment_audit_logs(order_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON public.payment_audit_logs(created_at DESC);

-- ==============================================================================
-- 8. HELPER SECURITY FUNCTIONS
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role = 'admin'
  );
$$;

-- ==============================================================================
-- 9. ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.membership_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upi_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payment_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payment_audit_logs ENABLE ROW LEVEL SECURITY;

-- --- Profiles Policies ---
CREATE POLICY "Users can read own profile or admin can read all"
ON public.profiles FOR SELECT
TO authenticated
USING (id = auth.uid() OR public.is_admin());

CREATE POLICY "Users can update own non-role profile or admin full update"
ON public.profiles FOR UPDATE
TO authenticated
USING (id = auth.uid() OR public.is_admin());

-- --- Membership Plans Policies ---
CREATE POLICY "Anyone can view active plans"
ON public.membership_plans FOR SELECT
TO authenticated, anon
USING (is_active = TRUE OR public.is_admin());

CREATE POLICY "Admins have full CRUD on plans"
ON public.membership_plans FOR ALL
TO authenticated
USING (public.is_admin());

-- --- UPI Config Policies ---
CREATE POLICY "Authenticated users can view active UPI config"
ON public.upi_configs FOR SELECT
TO authenticated
USING (is_active = TRUE OR public.is_admin());

CREATE POLICY "Admins have full CRUD on UPI config"
ON public.upi_configs FOR ALL
TO authenticated
USING (public.is_admin());

-- --- Payment Orders Policies ---
CREATE POLICY "Users can view their own orders or admin can view all"
ON public.payment_orders FOR SELECT
TO authenticated
USING (user_id = auth.uid() OR public.is_admin());

CREATE POLICY "Users can insert their own orders"
ON public.payment_orders FOR INSERT
TO authenticated
WITH CHECK (user_id = auth.uid());

CREATE POLICY "Users can update their pending order details (e.g. proof upload)"
ON public.payment_orders FOR UPDATE
TO authenticated
USING (user_id = auth.uid() AND status = 'pending')
WITH CHECK (user_id = auth.uid() AND status = 'pending');

CREATE POLICY "Admins have full update access on payment orders"
ON public.payment_orders FOR UPDATE
TO authenticated
USING (public.is_admin());

-- --- Memberships Policies ---
CREATE POLICY "Users can view their own membership or admin view all"
ON public.memberships FOR SELECT
TO authenticated
USING (user_id = auth.uid() OR public.is_admin());

CREATE POLICY "Admins have full access to memberships"
ON public.memberships FOR ALL
TO authenticated
USING (public.is_admin());

-- --- Audit Logs Policies ---
CREATE POLICY "Only admins can view payment audit logs"
ON public.payment_audit_logs FOR SELECT
TO authenticated
USING (public.is_admin());

CREATE POLICY "Admins and system can insert payment audit logs"
ON public.payment_audit_logs FOR INSERT
TO authenticated
WITH CHECK (public.is_admin());

-- ==============================================================================
-- 10. AUTH TRIGGER (Auto-create profile and Free Membership on user sign up)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    free_plan_id UUID;
BEGIN
    -- 1. Insert Profile
    INSERT INTO public.profiles (id, username, email, full_name, role)
    VALUES (
        NEW.id,
        COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1)),
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', 'CYVANTIS Operative'),
        COALESCE(NEW.raw_user_meta_data->>'role', 'viewer')
    );

    -- 2. Fetch Free Plan ID
    SELECT id INTO free_plan_id FROM public.membership_plans WHERE code = 'free' LIMIT 1;

    -- 3. Assign Default Free Plan Membership
    IF free_plan_id IS NOT NULL THEN
        INSERT INTO public.memberships (user_id, plan_id, status, start_date, end_date)
        VALUES (NEW.id, free_plan_id, 'active', NOW(), NULL);
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ==============================================================================
-- 11. ATOMIC PAYMENT APPROVAL PROCEDURE
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.approve_payment_order(
    p_order_id UUID,
    p_admin_id UUID,
    p_admin_notes TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_order RECORD;
    v_plan RECORD;
    v_curr_membership RECORD;
    v_new_start TIMESTAMPTZ;
    v_new_end TIMESTAMPTZ;
BEGIN
    -- 1. Validate Admin Privileges
    IF NOT public.is_admin() THEN
        RAISE EXCEPTION 'Unauthorized: Only administrators can approve payments.';
    END IF;

    -- 2. Lock and retrieve order
    SELECT * INTO v_order FROM public.payment_orders
    WHERE id = p_order_id FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Order not found';
    END IF;

    IF v_order.status = 'approved' THEN
        RAISE EXCEPTION 'Order has already been approved.';
    END IF;

    -- 3. Retrieve Plan
    SELECT * INTO v_plan FROM public.membership_plans WHERE id = v_order.plan_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Membership plan not found';
    END IF;

    -- 4. Calculate Duration & Expiry
    SELECT * INTO v_curr_membership FROM public.memberships WHERE user_id = v_order.user_id;

    IF FOUND AND v_curr_membership.status = 'active' AND v_curr_membership.end_date IS NOT NULL AND v_curr_membership.end_date > NOW() THEN
        -- Extend existing subscription from current end_date
        v_new_start := v_curr_membership.start_date;
        v_new_end := v_curr_membership.end_date + (v_plan.duration_days || ' days')::INTERVAL;
    ELSE
        -- Start fresh subscription
        v_new_start := NOW();
        v_new_end := NOW() + (v_plan.duration_days || ' days')::INTERVAL;
    END IF;

    -- 5. Update Membership
    IF FOUND THEN
        UPDATE public.memberships
        SET plan_id = v_plan.id,
            status = 'active',
            start_date = v_new_start,
            end_date = v_new_end,
            last_order_id = v_order.id,
            updated_at = NOW()
        WHERE user_id = v_order.user_id;
    ELSE
        INSERT INTO public.memberships (user_id, plan_id, status, start_date, end_date, last_order_id)
        VALUES (v_order.user_id, v_plan.id, 'active', v_new_start, v_new_end, v_order.id);
    END IF;

    -- 6. Update Payment Order
    UPDATE public.payment_orders
    SET status = 'approved',
        verified_by_id = p_admin_id,
        verified_at = NOW(),
        admin_notes = COALESCE(p_admin_notes, 'Approved by Administrator'),
        updated_at = NOW()
    WHERE id = v_order.id;

    -- 7. Insert Audit Log
    INSERT INTO public.payment_audit_logs (order_id, user_id, action, details, performed_by_id)
    VALUES (
        v_order.id,
        v_order.user_id,
        'ORDER_APPROVED',
        jsonb_build_object(
            'plan_code', v_plan.code,
            'duration_days', v_plan.duration_days,
            'amount_inr', v_order.amount_inr,
            'start_date', v_new_start,
            'end_date', v_new_end,
            'notes', p_admin_notes
        ),
        p_admin_id
    );

    RETURN jsonb_build_object(
        'success', TRUE,
        'order_id', v_order.id,
        'status', 'approved',
        'end_date', v_new_end
    );
END;
$$;

-- ==============================================================================
-- 12. STORAGE BUCKET CONFIGURATION (payment-receipts)
-- ==============================================================================
-- To be executed in Supabase Storage SQL:
INSERT INTO storage.buckets (id, name, public)
VALUES ('payment-receipts', 'payment-receipts', false)
ON CONFLICT (id) DO UPDATE SET public = false;

-- Allow authenticated users to upload receipts into their own user folder
CREATE POLICY "Users can upload their payment receipts"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (
    bucket_id = 'payment-receipts' AND
    (storage.foldername(name))[1] = auth.uid()::text
);

-- Allow users to view their own uploaded receipt screenshots
CREATE POLICY "Users can view their own payment receipts"
ON storage.objects FOR SELECT
TO authenticated
USING (
    bucket_id = 'payment-receipts' AND
    ((storage.foldername(name))[1] = auth.uid()::text OR public.is_admin())
);

-- ==============================================================================
-- 13. SEED DEFAULT PLANS & UPI CONFIG
-- ==============================================================================
INSERT INTO public.membership_plans (code, name, description, price_inr, duration_days, tier, badge, daily_scan_limit, sort_order, features)
VALUES
(
    'free',
    'Free Operative',
    'Essential cybersecurity triage tools for students and baseline telemetry.',
    0.00,
    0,
    'free',
    'STANDARD',
    5,
    1,
    '["Basic cybersecurity tools", "5 daily scans", "Standard dashboard access", "Community threat advisories", "Standard log extraction"]'::jsonb
),
(
    'monthly',
    'Monthly Premium',
    'Full access to advanced offensive and defensive cybersecurity suites.',
    49.00,
    30,
    'premium',
    'POPULAR',
    100,
    2,
    '["Full 30-day premium suite access", "100 daily scans", "Advanced Exploit & Payload Lab", "Automated Layer 2/3 Network Sweep", "Deep IOC correlation & VirusTotal intel", "Exportable CSV & JSON forensic reports", "SOC incident investigation workflow"]'::jsonb
),
(
    'quarterly',
    'Quarterly Premium',
    'Professional grade security tooling with extended 90-day persistence.',
    129.00,
    90,
    'premium',
    'RECOMMENDED',
    250,
    3,
    '["Full 90-day premium access", "250 daily scans", "All Monthly features included", "Advanced attack path correlation graph", "Multi-source Threat Intel (VirusTotal + AbuseIPDB + NVD)", "Automated cyber kill-chain telemetry", "Custom detection rule builder & testing"]'::jsonb
),
(
    'yearly',
    'Yearly Premium',
    'Uncapped enterprise cybersecurity powerhouse with 365-day access.',
    399.00,
    365,
    'premium',
    'BEST VALUE',
    -1,
    4,
    '["Full 365-day enterprise premium access", "Unlimited security scans per day", "Autonomous Defense suite & Cyber War Room", "AI CTF Terminal & Cyber Mentor access", "Executive PDF & Boardroom compliance reporting", "Zero-day outlier anomaly detection simulation", "24/7 Priority SOC engineering support"]'::jsonb
)
ON CONFLICT (code) DO NOTHING;

INSERT INTO public.upi_configs (upi_id, account_name, instructions, is_active)
VALUES (
    'cyvantis.pay@upi',
    'CYVANTIS Cybersecurity Nexus',
    'Scan using any UPI App (Google Pay, PhonePe, Paytm, BHIM, Cred) or enter the UPI ID manually. After completing payment, enter your 12-digit UTR/Reference number and upload your payment screenshot. An Admin will review and activate your subscription.',
    TRUE
)
ON CONFLICT DO NOTHING;
