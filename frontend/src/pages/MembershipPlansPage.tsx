import React, { useState, useEffect } from 'react';
import {
  Shield,
  Sparkles,
  Check,
  Zap,
  Lock,
  ArrowRight,
  HelpCircle,
  CreditCard,
  QrCode,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { membershipApi, MembershipPlan, UserSubscription } from '../services/membershipApi';
import { PremiumBadge } from '../components/membership/PremiumBadge';
import { PaymentCheckoutModal } from '../components/membership/PaymentCheckoutModal';

interface MembershipPlansPageProps {
  onNavigateToSubscription?: () => void;
}

export const MembershipPlansPage: React.FC<MembershipPlansPageProps> = ({
  onNavigateToSubscription
}) => {
  const [plans, setPlans] = useState<MembershipPlan[]>([]);
  const [currentSub, setCurrentSub] = useState<UserSubscription | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Selected plan for checkout modal
  const [selectedPlanForCheckout, setSelectedPlanForCheckout] = useState<MembershipPlan | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const [fetchedPlans, fetchedSub] = await Promise.all([
        membershipApi.getPlans(),
        membershipApi.getMySubscription()
      ]);
      setPlans(fetchedPlans);
      setCurrentSub(fetchedSub);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load membership plans.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectPlan = (plan: MembershipPlan) => {
    if (plan.tier === 'free') {
      alert('You are already entitled to baseline Free tools. Choose a Premium tier to unlock advanced exploit testing and network sweeps!');
      return;
    }
    setSelectedPlanForCheckout(plan);
    setIsModalOpen(true);
  };

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Hero Section */}
      <div className="relative rounded-3xl border border-cyan-500/20 bg-gradient-to-b from-[#091024] via-[#080E1E] to-[#040814] p-8 md:p-12 overflow-hidden shadow-[0_0_50px_rgba(6,182,212,0.1)]">
        {/* Ambient Glow & Grid Accent */}
        <div className="absolute top-0 right-0 -mr-20 -mt-20 w-80 h-80 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 -ml-20 -mb-20 w-80 h-80 rounded-full bg-blue-600/10 blur-3xl pointer-events-none" />

        <div className="relative z-10 max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono font-medium text-cyan-300 border border-cyan-500/30 bg-cyan-950/40 mb-4">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span>CYVANTIS AFFORDABLE CYBERSECURITY TIERS</span>
          </div>

          <h1 className="text-3xl md:text-5xl font-black text-white tracking-tight leading-tight mb-4">
            Supercharge Your SOC & Exploit Lab with <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">Premium Access</span>
          </h1>

          <p className="text-sm md:text-base text-slate-300 leading-relaxed mb-6">
            Engineered for security researchers, students, and active SOC analysts. Get full access to high-velocity payload generation, automated Layer 2/3 network sweeps, and enterprise threat intelligence starting at just <span className="text-cyan-400 font-bold">₹49/month</span>.
          </p>

          {/* Current Subscription Status Bar */}
          {currentSub && (
            <div className="flex flex-wrap items-center gap-4 p-4 rounded-2xl border border-slate-800 bg-slate-900/80 backdrop-blur-md">
              <div className="text-xs text-slate-400">
                <span>Active Status: </span>
                <span className="font-semibold text-white">{currentSub.plan_name}</span>
              </div>

              <PremiumBadge
                tier={currentSub.tier}
                status={currentSub.status}
                daysRemaining={currentSub.days_remaining}
                size="sm"
              />

              {currentSub.pending_order && (
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono bg-amber-500/10 border border-amber-500/30 text-amber-300">
                  <AlertCircle className="w-3.5 h-3.5" />
                  <span>Pending Order: {currentSub.pending_order.order_code} (Admin Review)</span>
                </div>
              )}

              {onNavigateToSubscription && (
                <button
                  onClick={onNavigateToSubscription}
                  className="ml-auto text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1"
                >
                  <span>Manage Subscription</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Pricing Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {isLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-96 rounded-2xl border border-slate-800 bg-slate-900/40 animate-pulse p-6"
            />
          ))
        ) : (
          plans.map((plan) => {
            const isFree = plan.tier === 'free';
            const isCurrentPlan = currentSub?.plan_code === plan.code && currentSub?.status === 'active';
            const isBestValue = plan.badge === 'BEST VALUE' || plan.code === 'yearly';
            const isPopular = plan.badge === 'POPULAR' || plan.code === 'monthly';

            return (
              <div
                key={plan.id}
                className={`relative flex flex-col justify-between rounded-2xl border p-6 transition-all duration-300 hover:-translate-y-1 ${
                  isBestValue
                    ? 'border-cyan-400/60 bg-gradient-to-b from-cyan-950/40 via-slate-900 to-slate-950 shadow-[0_0_35px_rgba(6,182,212,0.2)]'
                    : isPopular
                    ? 'border-blue-500/40 bg-gradient-to-b from-blue-950/30 via-slate-900 to-slate-950'
                    : 'border-slate-800 bg-slate-900/40 hover:border-slate-700'
                }`}
              >
                {/* Top Badge */}
                {plan.badge && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                    <span
                      className={`inline-block px-3 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-wider uppercase border shadow-md ${
                        isBestValue
                          ? 'border-cyan-400 bg-cyan-400 text-slate-950'
                          : 'border-blue-400 bg-blue-500/20 text-blue-300'
                      }`}
                    >
                      {plan.badge}
                    </span>
                  </div>
                )}

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-lg font-bold text-white tracking-wide">{plan.name}</h3>
                    {isFree ? (
                      <Shield className="w-5 h-5 text-slate-400" />
                    ) : (
                      <Zap className="w-5 h-5 text-cyan-400" />
                    )}
                  </div>

                  <p className="text-xs text-slate-400 mb-6 min-h-[32px] leading-relaxed">
                    {plan.description}
                  </p>

                  {/* Price */}
                  <div className="flex items-baseline gap-1.5 mb-6">
                    <span className="text-3xl md:text-4xl font-extrabold font-mono text-white">
                      ₹{plan.price_inr}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      {isFree ? '/ forever' : `/ ${plan.duration_days} days`}
                    </span>
                  </div>

                  {/* Features List */}
                  <div className="space-y-3 pt-4 border-t border-slate-800/80 mb-6">
                    <div className="text-[11px] font-mono font-semibold uppercase text-slate-400 tracking-wider">
                      Included Capabilities:
                    </div>
                    {plan.features.map((feature, idx) => (
                      <div key={idx} className="flex items-start gap-2.5 text-xs text-slate-300">
                        <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                        <span className="leading-snug">{feature}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Call to Action */}
                <div className="pt-4">
                  {isCurrentPlan ? (
                    <div className="w-full py-2.5 px-4 rounded-xl text-center text-xs font-semibold font-mono border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 flex items-center justify-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>YOUR CURRENT PLAN</span>
                    </div>
                  ) : (
                    <button
                      onClick={() => handleSelectPlan(plan)}
                      disabled={isFree}
                      className={`w-full py-2.5 px-4 rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2 ${
                        isFree
                          ? 'border border-slate-700 bg-slate-800/40 text-slate-400 cursor-default'
                          : isBestValue
                          ? 'bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-extrabold shadow-[0_0_20px_rgba(6,182,212,0.4)]'
                          : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_0_15px_rgba(6,182,212,0.3)]'
                      }`}
                    >
                      <span>{isFree ? 'Current Baseline' : `Upgrade to ${plan.name}`}</span>
                      {!isFree && <ArrowRight className="w-3.5 h-3.5" />}
                    </button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Feature Comparison Matrix & FAQ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 pt-6">
        {/* FAQ Left 2 Cols */}
        <div className="lg:col-span-2 rounded-2xl border border-slate-800 bg-slate-900/40 p-6">
          <div className="flex items-center gap-2 mb-6">
            <HelpCircle className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white tracking-wide">
              Frequently Asked Questions & Payment Protocol
            </h3>
          </div>

          <div className="space-y-4 text-xs">
            <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-950/60">
              <h5 className="font-semibold text-cyan-300 mb-1">
                How does UPI QR Verification work?
              </h5>
              <p className="text-slate-400 leading-relaxed">
                Scan the dynamic QR code with any UPI app (Google Pay, PhonePe, Paytm, BHIM, Cred) and pay the exact plan amount. Then enter your 12-digit UPI UTR number and upload a screenshot of the successful payment. A CYVANTIS Admin verifies the bank settlement before activating your membership.
              </p>
            </div>

            <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-950/60">
              <h5 className="font-semibold text-cyan-300 mb-1">
                How fast is membership activation?
              </h5>
              <p className="text-slate-400 leading-relaxed">
                Most UPI requests are reviewed within 15–30 minutes by our SOC desk. Once approved, your premium badge, increased scan quota, and locked exploit tools unlock instantly without needing to log out.
              </p>
            </div>

            <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-950/60">
              <h5 className="font-semibold text-cyan-300 mb-1">
                What happens when my subscription duration expires?
              </h5>
              <p className="text-slate-400 leading-relaxed">
                Your account gracefully transitions back to the Free Operative tier (5 daily scans and basic tools). Your historical logs, reports, and investigations are permanently preserved and never deleted.
              </p>
            </div>
          </div>
        </div>

        {/* Security Assurance Right 1 Col */}
        <div className="rounded-2xl border border-cyan-500/20 bg-gradient-to-b from-cyan-950/30 to-slate-900/60 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-4">
              <Shield className="w-5 h-5 text-cyan-400" />
              <h4 className="text-sm font-bold text-white">Security & Audit Compliance</h4>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              All payment submissions are verified against immutable audit logs. Screenshots are stored privately and never publicly indexed.
            </p>
            <div className="space-y-2 text-xs font-mono text-cyan-300">
              <div className="flex items-center gap-2">
                <Check className="w-3.5 h-3.5 text-cyan-400" />
                <span>Zero automatic screenshot approvals</span>
              </div>
              <div className="flex items-center gap-2">
                <Check className="w-3.5 h-3.5 text-cyan-400" />
                <span>Unique UTR duplicate prevention</span>
              </div>
              <div className="flex items-center gap-2">
                <Check className="w-3.5 h-3.5 text-cyan-400" />
                <span>Private receipt isolation</span>
              </div>
            </div>
          </div>

          <div className="pt-6 border-t border-slate-800/80 mt-6">
            <span className="text-[11px] text-slate-500 block">
              Official Payment Desk: <span className="text-slate-300 font-mono">cyvantis.pay@upi</span>
            </span>
          </div>
        </div>
      </div>

      {/* Payment Checkout Modal */}
      <PaymentCheckoutModal
        plan={selectedPlanForCheckout}
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setSelectedPlanForCheckout(null);
        }}
        onSuccess={() => {
          fetchData();
        }}
      />
    </div>
  );
};

export default MembershipPlansPage;
