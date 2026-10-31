import React from 'react';
import { Lock, Sparkles, ArrowRight, ShieldAlert } from 'lucide-react';

interface PremiumGateProps {
  isPremium: boolean;
  featureTitle: string;
  featureDescription?: string;
  onUpgradeClick?: () => void;
  children: React.ReactNode;
}

export const PremiumGate: React.FC<PremiumGateProps> = ({
  isPremium,
  featureTitle,
  featureDescription = 'This advanced cybersecurity module requires an active CYVANTIS Premium subscription.',
  onUpgradeClick,
  children
}) => {
  if (isPremium) {
    return <>{children}</>;
  }

  return (
    <div className="relative rounded-2xl border border-cyan-500/20 bg-gradient-to-b from-[#0A1124] to-[#060B18] p-8 text-center overflow-hidden shadow-[0_0_40px_rgba(6,11,24,0.8)]">
      {/* Background Cyber Grid Accent */}
      <div className="absolute inset-0 bg-[radial-gradient(#38bdf8_1px,transparent_1px)] [background-size:16px_16px] opacity-10 pointer-events-none" />

      <div className="relative z-10 max-w-xl mx-auto flex flex-col items-center">
        {/* Animated Lock Icon */}
        <div className="relative mb-5 flex items-center justify-center">
          <div className="absolute w-20 h-20 rounded-full bg-cyan-500/10 animate-ping opacity-25" />
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan-950 via-slate-900 to-blue-900 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_25px_rgba(56,189,248,0.3)]">
            <Lock className="w-8 h-8 text-cyan-400" />
          </div>
        </div>

        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium text-cyan-300 border border-cyan-500/30 bg-cyan-950/40 mb-3">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span>PREMIUM CYBER SUITE RESTRICTED</span>
        </div>

        <h3 className="text-xl font-bold text-white tracking-wide mb-2">
          {featureTitle} is Locked
        </h3>

        <p className="text-sm text-slate-400 mb-6 leading-relaxed">
          {featureDescription}
        </p>

        <div className="grid grid-cols-2 gap-3 w-full max-w-md mb-6 text-left">
          <div className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-slate-900/60 text-xs text-slate-300">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            <span>100–Unlimited Scans Daily</span>
          </div>
          <div className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-slate-900/60 text-xs text-slate-300">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            <span>Active Exploit Sandbox</span>
          </div>
          <div className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-slate-900/60 text-xs text-slate-300">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            <span>Full Threat Intel Feeds</span>
          </div>
          <div className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-slate-900/60 text-xs text-slate-300">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            <span>Boardroom PDF Reports</span>
          </div>
        </div>

        <button
          onClick={onUpgradeClick}
          className="inline-flex items-center gap-2 px-6 py-3 rounded-xl font-semibold text-sm bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white shadow-[0_0_20px_rgba(56,189,248,0.4)] transition-all transform hover:-translate-y-0.5 active:translate-y-0"
        >
          <span>Upgrade to Premium from ₹49</span>
          <ArrowRight className="w-4 h-4" />
        </button>

        <p className="text-[11px] text-slate-500 mt-3 flex items-center gap-1">
          <ShieldAlert className="w-3 h-3 text-cyan-400" />
          <span>Affordable security tools for students & SOC analysts. Instant verification via UPI.</span>
        </p>
      </div>
    </div>
  );
};

export default PremiumGate;

