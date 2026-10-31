import React, { useState, useEffect } from 'react';
import {
  Shield,
  Sparkles,
  Clock,
  Calendar,
  AlertCircle,
  CheckCircle2,
  XCircle,
  FileText,
  CreditCard,
  QrCode,
  ArrowUpRight,
  RefreshCw,
  ExternalLink,
  Zap
} from 'lucide-react';
import {
  membershipApi,
  UserSubscription,
  PaymentOrder,
  MembershipPlan
} from '../services/membershipApi';
import { PremiumBadge } from '../components/membership/PremiumBadge';
import { PaymentCheckoutModal } from '../components/membership/PaymentCheckoutModal';

interface MySubscriptionPageProps {
  onNavigateToPlans?: () => void;
}

const safeFeatures = (features: any): string[] => {
  if (Array.isArray(features)) return features;
  if (typeof features === 'string') {
    try {
      const parsed = JSON.parse(features);
      if (Array.isArray(parsed)) return parsed;
    } catch {
      return [features];
    }
  }
  return [];
};

export const MySubscriptionPage: React.FC<MySubscriptionPageProps> = ({
  onNavigateToPlans
}) => {
  const [subscription, setSubscription] = useState<UserSubscription | null>(null);
  const [orders, setOrders] = useState<PaymentOrder[]>([]);
  const [plans, setPlans] = useState<MembershipPlan[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Modal checkout
  const [selectedPlanForUpgrade, setSelectedPlanForUpgrade] = useState<MembershipPlan | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const [subData, orderList, plansList] = await Promise.all([
        membershipApi.getMySubscription(),
        membershipApi.getOrderHistory(),
        membershipApi.getPlans()
      ]);
      setSubscription(subData);
      setOrders(orderList);
      setPlans(plansList);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load subscription details.');
    } finally {
      setIsLoading(false);
    }
  };

  const openUpgradeModal = () => {
    // Pick the popular monthly plan or best value yearly plan
    const recommended = plans.find((p) => p.code === 'monthly') || plans.find((p) => p.tier === 'premium');
    if (recommended) {
      setSelectedPlanForUpgrade(recommended);
      setIsModalOpen(true);
    } else if (onNavigateToPlans) {
      onNavigateToPlans();
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'approved':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" />
            <span>APPROVED</span>
          </span>
        );
      case 'pending':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/30">
            <Clock className="w-3 h-3 animate-pulse" />
            <span>PENDING VERIFICATION</span>
          </span>
        );
      case 'rejected':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3 h-3" />
            <span>REJECTED</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            <span>{status.toUpperCase()}</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Sparkles className="w-5 h-5 text-cyan-400" />
            <h1 className="text-2xl font-bold text-white tracking-wide">
              My Subscription & Payment Desk
            </h1>
          </div>
          <p className="text-xs text-slate-400">
            Manage your CYVANTIS tier, review scan limits, and track payment verifications.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            className="p-2 rounded-xl border border-slate-800 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
            title="Refresh Subscription Data"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={openUpgradeModal}
            className="px-4 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all flex items-center gap-1.5"
          >
            <span>Upgrade / Extend Plan</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Pending Order Notice Banner */}
      {subscription?.pending_order && (
        <div className="p-4 rounded-2xl border border-amber-500/40 bg-gradient-to-r from-amber-950/40 to-slate-900/80 backdrop-blur-md flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400">
              <Clock className="w-5 h-5 animate-spin" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-white">
                Payment Verification Pending (Order {subscription.pending_order.order_code})
              </h4>
              <p className="text-xs text-slate-300 mt-0.5">
                Amount: <span className="font-mono text-cyan-400 font-semibold">₹{subscription.pending_order.amount_inr}</span> • Ref / UTR:{' '}
                <span className="font-mono text-white font-semibold">{subscription.pending_order.upi_ref_no || 'Submitted'}</span>. A SOC Admin is reviewing your receipt screenshot.
              </p>
            </div>
          </div>
          <span className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30">
            Awaiting Admin Approval
          </span>
        </div>
      )}

      {/* Main Grid: Active Plan Details + Scan Quotas */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Plan Card */}
        <div className="lg:col-span-2 rounded-2xl border border-slate-800 bg-[#090F1F] p-6 shadow-lg relative overflow-hidden">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div>
              <span className="text-xs font-mono uppercase text-slate-400 tracking-wider block mb-1">
                Current Active Tier
              </span>
              <h2 className="text-2xl font-black text-white tracking-wide">
                {subscription?.plan_name || 'Loading...'}
              </h2>
            </div>
            {subscription && (
              <PremiumBadge
                tier={subscription.tier}
                status={subscription.status}
                daysRemaining={subscription.days_remaining}
                size="md"
              />
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 py-6 border-b border-slate-800 text-xs">
            <div className="p-3 rounded-xl border border-slate-800/80 bg-slate-900/50">
              <span className="text-slate-400 block mb-1">Membership Status</span>
              <span className="text-sm font-bold font-mono text-white uppercase">
                {subscription?.status || 'Active'}
              </span>
            </div>

            <div className="p-3 rounded-xl border border-slate-800/80 bg-slate-900/50">
              <span className="text-slate-400 block mb-1">Expiration / Renewal</span>
              <span className="text-sm font-bold font-mono text-cyan-400">
                {subscription?.end_date
                  ? new Date(subscription.end_date).toLocaleDateString()
                  : 'Lifetime Free'}
              </span>
            </div>

            <div className="p-3 rounded-xl border border-slate-800/80 bg-slate-900/50">
              <span className="text-slate-400 block mb-1">Daily Scan Quota</span>
              <span className="text-sm font-bold font-mono text-emerald-400">
                {subscription?.daily_scan_limit === -1 ? 'Unlimited' : `${subscription?.daily_scan_limit || 5} scans / day`}
              </span>
            </div>
          </div>

          {/* Included Features */}
          <div className="pt-6">
            <h4 className="text-xs font-mono font-bold uppercase text-slate-400 tracking-wider mb-3">
              Active Entitlements:
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-300">
              {safeFeatures(subscription?.features).map((feat, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                  <span>{feat}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Upgrade / Next Tier Preview */}
        <div className="rounded-2xl border border-cyan-500/20 bg-gradient-to-b from-cyan-950/20 via-slate-900/40 to-slate-950 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Zap className="w-5 h-5 text-cyan-400" />
              <h3 className="text-base font-bold text-white">Need Higher Velocity?</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              Extend your duration or step up to the Yearly Premium Plan for unlimited scanning, autonomous defense simulations, and AI CTF sandbox access.
            </p>

            <div className="p-3.5 rounded-xl border border-cyan-500/30 bg-cyan-950/40 mb-4 text-xs font-mono">
              <div className="flex justify-between text-slate-400 mb-1">
                <span>Monthly:</span>
                <span className="text-cyan-300 font-bold">₹49 / 30d</span>
              </div>
              <div className="flex justify-between text-slate-400 mb-1">
                <span>Quarterly:</span>
                <span className="text-cyan-300 font-bold">₹129 / 90d</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Yearly (Uncapped):</span>
                <span className="text-emerald-400 font-bold">₹399 / 365d</span>
              </div>
            </div>
          </div>

          <button
            onClick={openUpgradeModal}
            className="w-full py-2.5 px-4 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all flex items-center justify-center gap-2"
          >
            <span>Subscribe / Renew via UPI</span>
            <ArrowUpRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Payment History Table */}
      <div className="rounded-2xl border border-slate-800 bg-[#090F1F] p-6 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white tracking-wide">
              Payment & Verification History
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {orders.length} Total Orders
          </span>
        </div>

        {orders.length === 0 ? (
          <div className="text-center py-10 border border-dashed border-slate-800 rounded-xl text-xs text-slate-500 font-mono">
            No payment orders found. Upgrade your plan to initialize your first order!
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 font-mono border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Order Code</th>
                  <th className="py-3 px-4">Plan</th>
                  <th className="py-3 px-4">Method</th>
                  <th className="py-3 px-4">Amount</th>
                  <th className="py-3 px-4">UPI / Gateway Ref</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Created Date</th>
                  <th className="py-3 px-4">Admin Notes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {orders.map((o) => (
                  <tr key={o.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-4 font-bold text-cyan-300">
                      {o.order_code}
                    </td>
                    <td className="py-3 px-4 text-white">
                      {o.plan_name || 'Premium'}
                    </td>
                    <td className="py-3 px-4 uppercase text-slate-400">
                      {o.payment_method === 'upi_qr' ? 'UPI QR' : 'Razorpay'}
                    </td>
                    <td className="py-3 px-4 font-bold text-white">
                      ₹{o.amount_inr}
                    </td>
                    <td className="py-3 px-4 text-slate-300 truncate max-w-xs">
                      {o.upi_ref_no || o.gateway_payment_id || '—'}
                    </td>
                    <td className="py-3 px-4">
                      {getStatusBadge(o.status)}
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {new Date(o.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-4 text-slate-400 truncate max-w-xs">
                      {o.admin_notes || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Payment Checkout Modal */}
      {selectedPlanForUpgrade && (
        <PaymentCheckoutModal
          plan={selectedPlanForUpgrade}
          isOpen={isModalOpen}
          onClose={() => {
            setIsModalOpen(false);
            setSelectedPlanForUpgrade(null);
          }}
          onSuccess={() => {
            loadData();
          }}
        />
      )}
    </div>
  );
};

export default MySubscriptionPage;
