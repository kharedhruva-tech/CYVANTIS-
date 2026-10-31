import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('CYVANTIS UI Render Crash Caught by ErrorBoundary:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[400px] flex items-center justify-center p-6">
          <div className="max-w-md w-full rounded-2xl border border-rose-500/30 bg-[#090F1F] p-6 text-center shadow-[0_0_40px_rgba(244,63,94,0.15)]">
            <div className="w-14 h-14 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 mx-auto mb-4">
              <AlertTriangle className="w-7 h-7" />
            </div>

            <h3 className="text-base font-bold text-white mb-2">
              {this.props.fallbackTitle || 'Interface Render Anomaly Detected'}
            </h3>

            <p className="text-xs text-slate-400 mb-4 leading-relaxed">
              An unexpected client error occurred while rendering this module. Telemetry has logged the issue for SOC triage.
            </p>

            {this.state.error && (
              <div className="p-3 rounded-xl border border-slate-800 bg-slate-950 font-mono text-[11px] text-rose-300 text-left mb-6 truncate max-w-full">
                {this.state.error.message || String(this.state.error)}
              </div>
            )}

            <div className="flex items-center justify-center gap-3">
              <button
                onClick={() => {
                  this.setState({ hasError: false, error: null });
                  if (this.props.onReset) this.props.onReset();
                  else window.location.reload();
                }}
                className="px-4 py-2 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(6,182,212,0.3)]"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Reload Module</span>
              </button>

              <button
                onClick={() => {
                  this.setState({ hasError: false, error: null });
                  window.location.href = '/';
                }}
                className="px-4 py-2 rounded-xl text-xs font-mono text-slate-400 hover:text-white border border-slate-800 hover:bg-slate-900 flex items-center gap-1.5 transition-colors"
              >
                <Home className="w-3.5 h-3.5" />
                <span>Overview</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
