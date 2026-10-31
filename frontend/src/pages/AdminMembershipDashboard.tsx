import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Users,
  CreditCard,
  CheckCircle2,
  XCircle,
  Clock,
  DollarSign,
  Search,
  ExternalLink,
  Edit,
  Save,
  RefreshCw,
  QrCode,
  Sliders,
  History,
  AlertTriangle,
  UserCheck,
  UserX,
  FileText,
  X
} from 'lucide-react';
import {
  membershipApi,
  AdminMembershipOverview,
  PaymentOrder,
  MembershipPlan,
  UpiConfig,
  PaymentAuditLog
} from '../services/membershipApi';

export const AdminMembershipDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'verification' | 'plans' | 'upi' | 'manual' | 'audit'>('verification');
  const [overview, setOverview] = useState<AdminMembershipOverview | null>(null);
  const [orders, setOrders] = useState<PaymentOrder[]>([]);
  const [plans, setPlans] = useState<MembershipPlan[]>([]);
  const [upiConfig, setUpiConfig] = useState<UpiConfig | null>(null);
  const [auditLogs, setAuditLogs] = useState<PaymentAuditLog[]>([]);

  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Filters
  const [orderStatusFilter, setOrderStatusFilter] = useState<'pending' | 'approved' | 'rejected' | 'all'>('pending');
  const [searchQuery, setSearchQuery] = useState('');

  // Screenshot Zoom Modal
  const [viewScreenshotUrl, setViewScreenshotUrl] = useState<string | null>(null);

  // Action processing
  const [processingOrderId, setProcessingOrderId] = useState<number | null>(null);
  const [actionNotes, setActionNotes] = useState<Record<number, string>>({});

  // Manual Membership state
  const [manualUserId, setManualUserId] = useState('');
  const [manualPlanCode, setManualPlanCode] = useState('monthly');
  const [manualDays, setManualDays] = useState('30');
  const [manualNotes, setManualNotes] = useState('Granted by SOC Administrator');
  const [isManualSubmitting, setIsManualSubmitting] = useState(false);

  // Plan editing state
  const [editingPlan, setEditingPlan] = useState<MembershipPlan | null>(null);
  const [isSavingPlan, setIsSavingPlan] = useState(false);

  // UPI Config edit state
  const [upiForm, setUpiForm] = useState<Partial<UpiConfig>>({});
  const [isSavingUpi, setIsSavingUpi] = useState(false);

  useEffect(() => {
    loadAllData();
  }, [orderStatusFilter]);

  const loadAllData = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const [ov, ords, plns, upi, logs] = await Promise.all([
        membershipApi.getAdminOverview(),
        membershipApi.getAdminOrders(orderStatusFilter === 'all' ? undefined : orderStatusFilter),
        membershipApi.getAdminPlans(),
        membershipApi.getAdminUpiConfig(),
        membershipApi.getAdminAuditLogs(50)
      ]);
      setOverview(ov);
      setOrders(ords);
      setPlans(plns);
      setUpiConfig(upi);
      setUpiForm(upi);
      setAuditLogs(logs);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch Admin membership data.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyOrder = async (orderId: number, action: 'approved' | 'rejected') => {
    const notes = actionNotes[orderId] || (action === 'approved' ? 'Verified and approved' : 'Payment rejected');
    if (action === 'rejected' && !confirm('Are you sure you want to REJECT this payment? The user will not receive membership access.')) {
      return;
    }

    setProcessingOrderId(orderId);
    setErrorMsg(null);
    try {
      await membershipApi.verifyAdminOrder(orderId, action, notes);
      setSuccessMsg(`Order #${orderId} successfully ${action.toUpperCase()}.`);
      setTimeout(() => setSuccessMsg(null), 4000);
      loadAllData();
    } catch (err: any) {
      setErrorMsg(err.message || `Failed to ${action} order.`);
    } finally {
      setProcessingOrderId(null);
    }
  };

  const handleManualActivate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualUserId || isNaN(Number(manualUserId))) {
      setErrorMsg('Please enter a valid numeric User ID.');
      return;
    }
    setIsManualSubmitting(true);
    setErrorMsg(null);
    try {
      const res = await membershipApi.manualActivate({
        user_id: Number(manualUserId),
        plan_code: manualPlanCode,
        duration_days: Number(manualDays),
        notes: manualNotes
      });
      setSuccessMsg(res.message);
      setManualUserId('');
      setTimeout(() => setSuccessMsg(null), 5000);
      loadAllData();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to manually activate membership.');
    } finally {
      setIsManualSubmitting(false);
    }
  };

  const handleSavePlan = async () => {
    if (!editingPlan) return;
    setIsSavingPlan(true);
    setErrorMsg(null);
    try {
      await membershipApi.updateAdminPlan(editingPlan.id, {
        price_inr: editingPlan.price_inr,
        duration_days: editingPlan.duration_days,
        daily_scan_limit: editingPlan.daily_scan_limit,
        is_active: editingPlan.is_active
      });
      setSuccessMsg(`Plan "${editingPlan.name}" updated successfully.`);
      setEditingPlan(null);
      setTimeout(() => setSuccessMsg(null), 4000);
      loadAllData();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to update plan.');
    } finally {
      setIsSavingPlan(false);
    }
  };

  const handleSaveUpi = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingUpi(true);
    setErrorMsg(null);
    try {
      const updated = await membershipApi.updateAdminUpiConfig(upiForm);
      setUpiConfig(updated);
      setSuccessMsg('UPI Configuration updated successfully.');
      setTimeout(() => setSuccessMsg(null), 4000);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to save UPI settings.');
    } finally {
      setIsSavingUpi(false);
    }
  };

  const filteredOrders = orders.filter((o) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      o.order_code.toLowerCase().includes(q) ||
      (o.username && o.username.toLowerCase().includes(q)) ||
      (o.upi_ref_no && o.upi_ref_no.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <h1 className="text-2xl font-bold text-white tracking-wide">
              Payment & Membership Command Desk
            </h1>
          </div>
          <p className="text-xs text-slate-400">
            Authorize UPI transactions, audit subscription renewals, and configure pricing tiers.
          </p>
        </div>

        <button
          onClick={loadAllData}
          className="p-2 rounded-xl border border-slate-800 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 transition-colors flex items-center gap-2 text-xs font-mono"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Data</span>
        </button>
      </div>

      {/* Notifications */}
      {errorMsg && (
        <div className="p-4 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}
      {successMsg && (
        <div className="p-4 rounded-xl border border-emerald-500/40 bg-emerald-500/10 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* KPI Overview Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="p-4 rounded-2xl border border-slate-800 bg-[#090F1F]">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase">Total Users</span>
            <Users className="w-4 h-4 text-cyan-400" />
          </div>
          <span className="text-2xl font-bold font-mono text-white">
            {overview?.total_users ?? '—'}
          </span>
        </div>

        <div className="p-4 rounded-2xl border border-cyan-500/30 bg-cyan-950/20">
          <div className="flex items-center justify-between text-cyan-400 mb-2">
            <span className="text-[11px] font-mono uppercase">Active Premium</span>
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
          </div>
          <span className="text-2xl font-bold font-mono text-cyan-300">
            {overview?.active_premium_users ?? '—'}
          </span>
        </div>

        <div className="p-4 rounded-2xl border border-amber-500/30 bg-amber-950/20">
          <div className="flex items-center justify-between text-amber-400 mb-2">
            <span className="text-[11px] font-mono uppercase">Pending Queue</span>
            <Clock className="w-4 h-4 text-amber-400 animate-pulse" />
          </div>
          <span className="text-2xl font-bold font-mono text-amber-300">
            {overview?.pending_verifications ?? '—'}
          </span>
        </div>

        <div className="p-4 rounded-2xl border border-emerald-500/30 bg-emerald-950/20">
          <div className="flex items-center justify-between text-emerald-400 mb-2">
            <span className="text-[11px] font-mono uppercase">Approved</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <span className="text-2xl font-bold font-mono text-emerald-300">
            {overview?.approved_orders ?? '—'}
          </span>
        </div>

        <div className="p-4 rounded-2xl border border-rose-500/30 bg-rose-950/20">
          <div className="flex items-center justify-between text-rose-400 mb-2">
            <span className="text-[11px] font-mono uppercase">Rejected</span>
            <XCircle className="w-4 h-4 text-rose-400" />
          </div>
          <span className="text-2xl font-bold font-mono text-rose-300">
            {overview?.rejected_orders ?? '—'}
          </span>
        </div>

        <div className="p-4 rounded-2xl border border-slate-800 bg-[#090F1F]">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase">Total Revenue</span>
            <DollarSign className="w-4 h-4 text-emerald-400" />
          </div>
          <span className="text-2xl font-bold font-mono text-white">
            ₹{overview?.total_revenue_inr ?? '0'}
          </span>
        </div>
      </div>

      {/* Tabs Switcher */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveTab('verification')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'verification'
              ? 'bg-cyan-500 text-slate-950 shadow-[0_0_15px_rgba(6,182,212,0.3)]'
              : 'text-slate-400 hover:text-white bg-slate-900/60 border border-slate-800'
          }`}
        >
          <Clock className="w-4 h-4" />
          <span>Payment Verification Queue</span>
          {Boolean(overview?.pending_verifications) && (
            <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-amber-400 text-slate-950 font-extrabold">
              {overview?.pending_verifications}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('manual')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'manual'
              ? 'bg-cyan-500 text-slate-950 shadow-[0_0_15px_rgba(6,182,212,0.3)]'
              : 'text-slate-400 hover:text-white bg-slate-900/60 border border-slate-800'
          }`}
        >
          <UserCheck className="w-4 h-4" />
          <span>User Grant / Revoke</span>
        </button>

        <button
          onClick={() => setActiveTab('plans')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'plans'
              ? 'bg-cyan-500 text-slate-950 shadow-[0_0_15px_rgba(6,182,212,0.3)]'
              : 'text-slate-400 hover:text-white bg-slate-900/60 border border-slate-800'
          }`}
        >
          <Sliders className="w-4 h-4" />
          <span>Plan Configurations</span>
        </button>

        <button
          onClick={() => setActiveTab('upi')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'upi'
              ? 'bg-cyan-500 text-slate-950 shadow-[0_0_15px_rgba(6,182,212,0.3)]'
              : 'text-slate-400 hover:text-white bg-slate-900/60 border border-slate-800'
          }`}
        >
          <QrCode className="w-4 h-4" />
          <span>UPI QR Settings</span>
        </button>

        <button
          onClick={() => setActiveTab('audit')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'audit'
              ? 'bg-cyan-500 text-slate-950 shadow-[0_0_15px_rgba(6,182,212,0.3)]'
              : 'text-slate-400 hover:text-white bg-slate-900/60 border border-slate-800'
          }`}
        >
          <History className="w-4 h-4" />
          <span>Payment Audit Logs</span>
        </button>
      </div>

      {/* Tab 1: Payment Verification Queue */}
      {activeTab === 'verification' && (
        <div className="rounded-2xl border border-slate-800 bg-[#090F1F] p-6 shadow-lg">
          {/* Controls bar */}
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-6">
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search order code, username, or UTR..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs font-mono text-white placeholder-slate-500 outline-none w-64 md:w-80"
                />
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Filter Status:</span>
              {(['pending', 'approved', 'rejected', 'all'] as const).map((st) => (
                <button
                  key={st}
                  onClick={() => setOrderStatusFilter(st)}
                  className={`px-3 py-1 rounded-lg text-xs font-mono uppercase transition-colors ${
                    orderStatusFilter === st
                      ? 'bg-slate-800 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          {filteredOrders.length === 0 ? (
            <div className="text-center py-12 border border-dashed border-slate-800 rounded-xl text-xs text-slate-500 font-mono">
              No payment orders matching current filter.
            </div>
          ) : (
            <div className="space-y-4">
              {filteredOrders.map((order) => {
                const isPending = order.status === 'pending';
                const isProcessing = processingOrderId === order.id;

                return (
                  <div
                    key={order.id}
                    className={`p-5 rounded-2xl border transition-all ${
                      isPending
                        ? 'border-amber-500/30 bg-gradient-to-r from-amber-950/10 via-slate-900 to-slate-950'
                        : 'border-slate-800/80 bg-slate-900/40'
                    }`}
                  >
                    <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
                      {/* Left Details */}
                      <div className="space-y-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-sm font-bold text-cyan-300">
                            {order.order_code}
                          </span>
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-slate-800 text-slate-300">
                            {order.plan_name}
                          </span>
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/30">
                            ₹{order.amount_inr}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                              order.status === 'approved'
                                ? 'bg-emerald-500/20 text-emerald-400'
                                : order.status === 'pending'
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-rose-500/20 text-rose-400'
                            }`}
                          >
                            {order.status}
                          </span>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-x-6 gap-y-1 text-xs text-slate-400 font-mono">
                          <div>
                            User: <span className="text-white font-medium">{order.username || `User #${order.user_id}`}</span>
                          </div>
                          <div>
                            UTR / Ref:{' '}
                            <span className="text-white font-bold select-all">
                              {order.upi_ref_no || order.gateway_payment_id || 'Not provided'}
                            </span>
                          </div>
                          <div>
                            Submitted:{' '}
                            <span className="text-slate-300">
                              {new Date(order.created_at).toLocaleString()}
                            </span>
                          </div>
                        </div>

                        {order.admin_notes && (
                          <div className="text-xs text-slate-400">
                            <span className="font-semibold text-slate-300">Admin Note: </span>
                            <span>{order.admin_notes}</span>
                          </div>
                        )}
                      </div>

                      {/* Right Actions & Receipt Preview */}
                      <div className="flex flex-wrap items-center gap-3">
                        {order.receipt_screenshot_url && (
                          <button
                            onClick={() => setViewScreenshotUrl(membershipApi.getReceiptUrl(order.receipt_screenshot_url!))}
                            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-mono border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 transition-colors"
                          >
                            <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                            <span>View Receipt</span>
                          </button>
                        )}

                        {isPending && (
                          <div className="flex items-center gap-2">
                            <input
                              type="text"
                              placeholder="Optional verification note..."
                              value={actionNotes[order.id] || ''}
                              onChange={(e) =>
                                setActionNotes({ ...actionNotes, [order.id]: e.target.value })
                              }
                              className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-white placeholder-slate-600 outline-none w-48"
                            />

                            <button
                              disabled={isProcessing}
                              onClick={() => handleVerifyOrder(order.id, 'approved')}
                              className="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 shadow-[0_0_12px_rgba(16,185,129,0.3)] transition-all flex items-center gap-1"
                            >
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>Approve</span>
                            </button>

                            <button
                              disabled={isProcessing}
                              onClick={() => handleVerifyOrder(order.id, 'rejected')}
                              className="px-3 py-1.5 rounded-xl text-xs font-bold bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 transition-all flex items-center gap-1"
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              <span>Reject</span>
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: User Grant / Revoke */}
      {activeTab === 'manual' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="rounded-2xl border border-slate-800 bg-[#090F1F] p-6 shadow-lg">
            <div className="flex items-center gap-2 mb-4">
              <UserCheck className="w-5 h-5 text-cyan-400" />
              <h3 className="text-base font-bold text-white tracking-wide">
                Direct User Membership Activation
              </h3>
            </div>
            <p className="text-xs text-slate-400 mb-6 leading-relaxed">
              Manually activate or renew a subscription for a student, corporate demo account, or offline wire settlement.
            </p>

            <form onSubmit={handleManualActivate} className="space-y-4">
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1">
                  Target User ID (Numeric) <span className="text-rose-400">*</span>
                </label>
                <input
                  type="number"
                  required
                  placeholder="e.g. 2"
                  value={manualUserId}
                  onChange={(e) => setManualUserId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs font-mono text-white outline-none focus:border-cyan-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">
                    Membership Plan
                  </label>
                  <select
                    value={manualPlanCode}
                    onChange={(e) => setManualPlanCode(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white outline-none"
                  >
                    <option value="monthly">Monthly Premium (₹49)</option>
                    <option value="quarterly">Quarterly Premium (₹129)</option>
                    <option value="yearly">Yearly Premium (₹399)</option>
                    <option value="free">Reset to Free Tier</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">
                    Duration (Days)
                  </label>
                  <input
                    type="number"
                    value={manualDays}
                    onChange={(e) => setManualDays(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1">
                  Audit Notes / Reason
                </label>
                <input
                  type="text"
                  value={manualNotes}
                  onChange={(e) => setManualNotes(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={isManualSubmitting || !manualUserId}
                className="w-full py-2.5 px-4 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all flex items-center justify-center gap-2"
              >
                <UserCheck className="w-4 h-4" />
                <span>{isManualSubmitting ? 'Granting...' : 'Activate Membership'}</span>
              </button>
            </form>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-[#090F1F] p-6 shadow-lg">
            <div className="flex items-center gap-2 mb-4">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
              <h3 className="text-base font-bold text-white tracking-wide">
                Role & Entitlement Governance
              </h3>
            </div>
            <div className="space-y-4 text-xs text-slate-300 leading-relaxed">
              <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/60">
                <span className="font-bold text-white block mb-1">Admin Enterprise Exemption</span>
                <p className="text-slate-400">
                  Accounts with <code className="text-cyan-300">admin</code> role have permanent enterprise clearance and can execute all premium penetration testing tools automatically.
                </p>
              </div>

              <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/60">
                <span className="font-bold text-white block mb-1">Atomic Subscription Extension</span>
                <p className="text-slate-400">
                  If an active premium user buys or is granted an extension, the days are appended to their existing expiration date rather than resetting from today.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Plan Configurations */}
      {activeTab === 'plans' && (
        <div className="rounded-2xl border border-slate-800 bg-[#090F1F] p-6 shadow-lg">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-base font-bold text-white tracking-wide">
                Configurable Membership Plans
              </h3>
              <p className="text-xs text-slate-400">
                Modify pricing, durations, and scan limits without rebuilding frontend or database.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {plans.map((p) => {
              const isEditing = editingPlan?.id === p.id;
              const current = isEditing ? editingPlan : p;

              return (
                <div
                  key={p.id}
                  className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-bold text-white text-sm">{current.name}</h4>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        {current.code}
                      </span>
                    </div>

                    <div className="space-y-3 pt-3 border-t border-slate-800 text-xs">
                      <div>
                        <label className="text-[10px] uppercase font-mono text-slate-400 block mb-0.5">
                          Price (INR ₹)
                        </label>
                        {isEditing ? (
                          <input
                            type="number"
                            value={current.price_inr}
                            onChange={(e) =>
                              setEditingPlan({ ...current, price_inr: Number(e.target.value) })
                            }
                            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-xs font-mono text-cyan-300"
                          />
                        ) : (
                          <span className="font-bold font-mono text-cyan-300">
                            ₹{current.price_inr}
                          </span>
                        )}
                      </div>

                      <div>
                        <label className="text-[10px] uppercase font-mono text-slate-400 block mb-0.5">
                          Duration (Days)
                        </label>
                        {isEditing ? (
                          <input
                            type="number"
                            value={current.duration_days}
                            onChange={(e) =>
                              setEditingPlan({ ...current, duration_days: Number(e.target.value) })
                            }
                            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-xs font-mono text-white"
                          />
                        ) : (
                          <span className="font-mono text-white">
                            {current.duration_days} Days
                          </span>
                        )}
                      </div>

                      <div>
                        <label className="text-[10px] uppercase font-mono text-slate-400 block mb-0.5">
                          Daily Scan Limit (-1 = Unlimited)
                        </label>
                        {isEditing ? (
                          <input
                            type="number"
                            value={current.daily_scan_limit}
                            onChange={(e) =>
                              setEditingPlan({ ...current, daily_scan_limit: Number(e.target.value) })
                            }
                            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-xs font-mono text-white"
                          />
                        ) : (
                          <span className="font-mono text-emerald-400">
                            {current.daily_scan_limit === -1 ? 'Unlimited' : current.daily_scan_limit}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-slate-800 mt-4">
                    {isEditing ? (
                      <div className="flex items-center gap-2">
                        <button
                          onClick={handleSavePlan}
                          disabled={isSavingPlan}
                          className="flex-1 py-1.5 px-3 rounded-lg text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 flex items-center justify-center gap-1"
                        >
                          <Save className="w-3.5 h-3.5" />
                          <span>Save</span>
                        </button>
                        <button
                          onClick={() => setEditingPlan(null)}
                          className="py-1.5 px-3 rounded-lg text-xs font-mono text-slate-400 hover:text-white"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setEditingPlan(p)}
                        className="w-full py-1.5 px-3 rounded-lg text-xs font-mono border border-slate-700 hover:bg-slate-800 text-slate-300 transition-colors flex items-center justify-center gap-1.5"
                      >
                        <Edit className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Edit Plan</span>
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 4: UPI QR Settings */}
      {activeTab === 'upi' && (
        <div className="max-w-2xl rounded-2xl border border-slate-800 bg-[#090F1F] p-6 shadow-lg">
          <div className="flex items-center gap-2 mb-4">
            <QrCode className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white tracking-wide">
              Official UPI QR & Gateway Settings
            </h3>
          </div>
          <p className="text-xs text-slate-400 mb-6 leading-relaxed">
            Configure the default VPA address and instructions presented on user checkout.
          </p>

          <form onSubmit={handleSaveUpi} className="space-y-4 text-xs">
            <div>
              <label className="font-medium text-slate-300 block mb-1">
                UPI ID (Virtual Payment Address) <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                required
                value={upiForm.upi_id || ''}
                onChange={(e) => setUpiForm({ ...upiForm, upi_id: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 font-mono text-white outline-none focus:border-cyan-400"
              />
            </div>

            <div>
              <label className="font-medium text-slate-300 block mb-1">
                Official Payee / Account Name <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                required
                value={upiForm.account_name || ''}
                onChange={(e) => setUpiForm({ ...upiForm, account_name: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-white outline-none focus:border-cyan-400"
              />
            </div>

            <div>
              <label className="font-medium text-slate-300 block mb-1">
                User Instructions
              </label>
              <textarea
                rows={3}
                value={upiForm.instructions || ''}
                onChange={(e) => setUpiForm({ ...upiForm, instructions: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-white outline-none focus:border-cyan-400"
              />
            </div>

            <button
              type="submit"
              disabled={isSavingUpi}
              className="py-2.5 px-6 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all flex items-center gap-2"
            >
              <Save className="w-4 h-4" />
              <span>{isSavingUpi ? 'Saving...' : 'Save UPI Configuration'}</span>
            </button>
          </form>
        </div>
      )}

      {/* Tab 5: Payment Audit Logs */}
      {activeTab === 'audit' && (
        <div className="rounded-2xl border border-slate-800 bg-[#090F1F] p-6 shadow-lg">
          <div className="flex items-center gap-2 mb-4">
            <History className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white tracking-wide">
              Immutable Verification Audit Logs
            </h3>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Order ID</th>
                  <th className="py-3 px-4">Actor</th>
                  <th className="py-3 px-4">Details</th>
                  <th className="py-3 px-4">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-4 font-bold text-cyan-300">
                      {log.action}
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {log.order_id ? `#${log.order_id}` : 'System'}
                    </td>
                    <td className="py-3 px-4 text-white">
                      {log.performed_by_name || 'System / Admin'}
                    </td>
                    <td className="py-3 px-4 text-slate-400 max-w-md truncate">
                      {log.details ? JSON.stringify(log.details) : '—'}
                    </td>
                    <td className="py-3 px-4 text-slate-500">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Screenshot Zoom Modal */}
      {viewScreenshotUrl && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/90 backdrop-blur-md">
          <div className="relative max-w-3xl max-h-[90vh] bg-slate-950 border border-slate-800 rounded-2xl p-4 shadow-2xl overflow-hidden flex flex-col items-center">
            <div className="w-full flex justify-between items-center pb-3 border-b border-slate-800 mb-3">
              <span className="text-xs font-mono text-cyan-400 font-bold">
                UPI Payment Receipt Inspection
              </span>
              <button
                onClick={() => setViewScreenshotUrl(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <img
              src={viewScreenshotUrl}
              alt="Payment proof receipt"
              className="max-h-[75vh] object-contain rounded-lg"
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminMembershipDashboard;

