import React from 'react';
import { Shield, Sparkles, AlertCircle, Clock } from 'lucide-react';

interface PremiumBadgeProps {
  tier?: 'free' | 'premium' | string;
  status?: 'active' | 'expired' | 'revoked' | 'none';
  daysRemaining?: number | null;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const PremiumBadge: React.FC<PremiumBadgeProps> = ({
  tier = 'free',
  status = 'active',
  daysRemaining,
  size = 'md',
  className = ''
}) => {
  const isPremium = tier.toLowerCase() === 'premium' || tier.toLowerCase().includes('premium');
  const isExpired = status === 'expired' || status === 'revoked';

  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5 tracking-wider gap-1',
    md: 'text-xs px-2.5 py-1 tracking-wider gap-1.5',
    lg: 'text-sm px-3.5 py-1.5 tracking-wide gap-2'
  }[size];

  if (isExpired) {
    return (
      <span
        className={`inline-flex items-center rounded-full font-mono font-semibold uppercase border border-rose-500/40 bg-rose-500/10 text-rose-400 shadow-[0_0_12px_rgba(244,63,94,0.15)] ${sizeClasses} ${className}`}
      >
        <AlertCircle className={size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'} />
        <span>EXPIRED</span>
      </span>
    );
  }

  if (isPremium) {
    return (
      <div className={`inline-flex items-center gap-1.5 ${className}`}>
        <span
          className={`inline-flex items-center rounded-full font-mono font-semibold uppercase border border-cyan-400/40 bg-gradient-to-r from-cyan-950/60 to-blue-900/60 text-cyan-300 shadow-[0_0_15px_rgba(56,189,248,0.25)] ${sizeClasses}`}
        >
          <Sparkles className={`text-cyan-400 animate-pulse ${size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'}`} />
          <span>CYVANTIS PREMIUM</span>
        </span>
        {typeof daysRemaining === 'number' && daysRemaining >= 0 && (
          <span
            className={`inline-flex items-center font-mono rounded-full border border-slate-700 bg-slate-900/80 text-slate-300 ${sizeClasses}`}
            title={`${daysRemaining} days left`}
          >
            <Clock className={size === 'sm' ? 'w-2.5 h-2.5 text-slate-400' : 'w-3.5 h-3.5 text-slate-400'} />
            <span>{daysRemaining}d left</span>
          </span>
        )}
      </div>
    );
  }

  return (
    <span
      className={`inline-flex items-center rounded-full font-mono font-medium uppercase border border-slate-700 bg-slate-800/60 text-slate-400 ${sizeClasses} ${className}`}
    >
      <Shield className={size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'} />
      <span>FREE TIER</span>
    </span>
  );
};

export default PremiumBadge;
