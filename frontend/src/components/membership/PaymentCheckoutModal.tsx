import React, { useState, useEffect } from 'react';
import {
  X,
  QrCode,
  CreditCard,
  Copy,
  Check,
  Upload,
  AlertTriangle,
  Clock,
  Sparkles,
  ShieldCheck,
  FileText
} from 'lucide-react';
import { membershipApi, MembershipPlan, PaymentOrder, UpiConfig } from '../../services/membershipApi';

interface PaymentCheckoutModalProps {
  plan: MembershipPlan | null;
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

export const PaymentCheckoutModal: React.FC<PaymentCheckoutModalProps> = ({
  plan,
  isOpen,
  onClose,
  onSuccess
}) => {
  const [paymentMethod, setPaymentMethod] = useState<'upi_qr' | 'razorpay'>('upi_qr');
  const [upiConfig, setUpiConfig] = useState<UpiConfig | null>(null);
  const [createdOrder, setCreatedOrder] = useState<PaymentOrder | null>(null);
  const [isInitializing, setIsInitializing] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // UPI Form state
  const [upiRefNo, setUpiRefNo] = useState('');
  const [receiptFile, setReceiptFile] = useState<File | null>(null);
  const [receiptPreview, setReceiptPreview] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Success / Pending Review state
  const [isSubmitted, setIsSubmitted] = useState(false);

  useEffect(() => {
    if (isOpen && plan) {
      initCheckout();
    } else {
      // Reset state
      setCreatedOrder(null);
      setUpiRefNo('');
      setReceiptFile(null);
      setReceiptPreview(null);
      setErrorMsg(null);
      setIsSubmitted(false);
    }
  }, [isOpen, plan]);

  const initCheckout = async () => {
    if (!plan) return;
    setIsInitializing(true);
    setErrorMsg(null);
    try {
      // Fetch active UPI config
      const cfg = await membershipApi.getUpiConfig();
      setUpiConfig(cfg);

      // Create initial pending order
      const order = await membershipApi.createOrder(plan.id, paymentMethod);
      setCreatedOrder(order);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to initialize payment checkout.');
    } finally {
      setIsInitializing(false);
    }
  };

  const handleCopy = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) {
        setErrorMsg('Invalid format. Please upload a JPG, PNG, or WEBP receipt.');
        return;
      }
      if (file.size > 5 * 1024 * 1024) {
        setErrorMsg('File too large. Maximum screenshot size is 5MB.');
        return;
      }
      setErrorMsg(null);
      setReceiptFile(file);
      setReceiptPreview(URL.createObjectURL(file));
    }
  };

  const handleUpiSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createdOrder) {
      setErrorMsg('No active order found.');
      return;
    }
    if (!upiRefNo || upiRefNo.trim().length < 8) {
      setErrorMsg('Please enter a valid 12-digit UPI Reference / UTR Number.');
      return;
    }
    if (!receiptFile) {
      setErrorMsg('Please upload a screenshot of your UPI payment receipt.');
      return;
    }

    setIsSubmitting(true);
    setErrorMsg(null);
    try {
      await membershipApi.submitUpiPayment(createdOrder.order_code, upiRefNo.trim(), receiptFile);
      setIsSubmitted(true);
      if (onSuccess) onSuccess();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to submit payment proof.');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!isOpen || !plan) return null;

  // Generate dynamic UPI Payment Deep Link & QR Code URL
  const targetUpiId = upiConfig?.upi_id || 'cyvantis.pay@upi';
  const targetPayee = upiConfig?.account_name || 'CYVANTIS Cybersecurity';
  const orderRef = createdOrder?.order_code || 'CYV-ORDER';
  const upiIntentUri = `upi://pay?pa=${encodeURIComponent(targetUpiId)}&pn=${encodeURIComponent(targetPayee)}&am=${plan.price_inr}&cu=INR&tn=${encodeURIComponent(orderRef)}`;
  // High reliability SVG QR via Google Charts / QuickChart API
  const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&margin=10&data=${encodeURIComponent(upiIntentUri)}`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md overflow-y-auto">
      <div className="relative w-full max-w-2xl bg-[#090F1F] border border-cyan-500/30 rounded-2xl shadow-[0_0_50px_rgba(6,182,212,0.15)] overflow-hidden my-8">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-wide">
                CYVANTIS Secure Checkout
              </h3>
              <p className="text-xs text-slate-400">
                Plan: <span className="text-cyan-400 font-semibold">{plan.name}</span> • ₹{plan.price_inr} for {plan.duration_days} Days
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6">
          {isSubmitted ? (
            /* Submission Success State */
            <div className="text-center py-6">
              <div className="w-16 h-16 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 mx-auto mb-4 shadow-[0_0_20px_rgba(245,158,11,0.2)]">
                <Clock className="w-8 h-8 animate-pulse" />
              </div>
              <h4 className="text-xl font-bold text-white mb-2">Payment Submitted for Admin Verification</h4>
              <p className="text-sm text-slate-300 max-w-md mx-auto mb-6">
                Your order <span className="font-mono text-cyan-400 font-bold">{createdOrder?.order_code}</span> and UTR{' '}
                <span className="font-mono text-white font-bold">{upiRefNo}</span> have been placed in the SOC verification queue.
              </p>

              <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/80 max-w-md mx-auto text-left text-xs text-slate-400 mb-6 space-y-2">
                <div className="flex justify-between">
                  <span>Selected Plan:</span>
                  <span className="text-white font-semibold">{plan.name}</span>
                </div>
                <div className="flex justify-between">
                  <span>Amount Paid:</span>
                  <span className="text-cyan-400 font-semibold">₹{plan.price_inr}</span>
                </div>
                <div className="flex justify-between">
                  <span>Current Status:</span>
                  <span className="text-amber-400 font-semibold uppercase">Pending Admin Approval</span>
                </div>
                <div className="flex justify-between">
                  <span>Turnaround Time:</span>
                  <span className="text-slate-300">Within 15–30 minutes</span>
                </div>
              </div>

              <div className="flex justify-center gap-3">
                <button
                  onClick={onClose}
                  className="px-6 py-2.5 rounded-xl text-sm font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all"
                >
                  Return to Dashboard
                </button>
              </div>
            </div>
          ) : (
            /* Checkout Tabs & Payment UI */
            <div>
              {/* Payment Method Switcher */}
              <div className="grid grid-cols-2 gap-3 mb-6">
                <button
                  type="button"
                  onClick={() => setPaymentMethod('upi_qr')}
                  className={`flex items-center justify-center gap-2 p-3 rounded-xl border text-sm font-semibold transition-all ${
                    paymentMethod === 'upi_qr'
                      ? 'border-cyan-500 bg-cyan-950/40 text-cyan-300 shadow-[0_0_15px_rgba(6,182,212,0.2)]'
                      : 'border-slate-800 bg-slate-900/40 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <QrCode className="w-4 h-4 text-cyan-400" />
                  <span>UPI QR / VPA (Fastest)</span>
                </button>
                <button
                  type="button"
                  onClick={() => setPaymentMethod('razorpay')}
                  className={`flex items-center justify-center gap-2 p-3 rounded-xl border text-sm font-semibold transition-all ${
                    paymentMethod === 'razorpay'
                      ? 'border-cyan-500 bg-cyan-950/40 text-cyan-300 shadow-[0_0_15px_rgba(6,182,212,0.2)]'
                      : 'border-slate-800 bg-slate-900/40 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <CreditCard className="w-4 h-4 text-cyan-400" />
                  <span>Cards / NetBanking</span>
                </button>
              </div>

              {errorMsg && (
                <div className="mb-4 p-3 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-300 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                  <span>{errorMsg}</span>
                </div>
              )}

              {paymentMethod === 'upi_qr' ? (
                /* Method A: UPI QR Payment */
                <div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-start">
                    {/* Left: Dynamic QR Code Box */}
                    <div className="flex flex-col items-center p-4 rounded-xl border border-slate-800 bg-slate-950/80 text-center">
                      <div className="relative p-3 bg-white rounded-xl shadow-lg mb-3">
                        {isInitializing ? (
                          <div className="w-44 h-44 flex items-center justify-center text-slate-400 text-xs font-mono">
                            Loading QR...
                          </div>
                        ) : (
                          <img
                            src={qrCodeUrl}
                            alt="UPI Payment QR"
                            className="w-44 h-44 object-contain rounded"
                          />
                        )}
                      </div>

                      <span className="text-[11px] font-mono text-cyan-300 font-semibold mb-1">
                        Scan with GPay / PhonePe / Paytm / BHIM
                      </span>
                      <span className="text-[10px] text-slate-500">
                        Order ID: {createdOrder?.order_code || 'CYV-...'}
                      </span>

                      {/* Deep Link button on Mobile */}
                      <a
                        href={upiIntentUri}
                        className="mt-3 w-full py-1.5 px-3 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors md:hidden text-center"
                      >
                        Open in UPI App
                      </a>
                    </div>

                    {/* Right: Payment Instructions & Details */}
                    <div className="space-y-4">
                      {/* Amount Card */}
                      <div className="p-3 rounded-xl border border-cyan-500/20 bg-cyan-950/20 flex items-center justify-between">
                        <div>
                          <span className="text-xs text-slate-400 block">Total Payable:</span>
                          <span className="text-2xl font-bold font-mono text-cyan-300">
                            ₹{plan.price_inr}
                          </span>
                        </div>
                        <button
                          onClick={() => handleCopy(String(plan.price_inr), 'amount')}
                          className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-mono border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10"
                        >
                          {copiedField === 'amount' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                          <span>{copiedField === 'amount' ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>

                      {/* UPI ID Field */}
                      <div>
                        <label className="text-xs font-medium text-slate-300 block mb-1">
                          Official UPI ID (VPA)
                        </label>
                        <div className="flex items-center gap-2">
                          <input
                            type="text"
                            readOnly
                            value={targetUpiId}
                            className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-200 outline-none"
                          />
                          <button
                            onClick={() => handleCopy(targetUpiId, 'upi')}
                            className="p-2 rounded-xl border border-slate-700 bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
                            title="Copy UPI ID"
                          >
                            {copiedField === 'upi' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>

                      {/* Payee Info */}
                      <div className="text-xs text-slate-400">
                        <span>Payee: </span>
                        <span className="text-slate-200 font-medium">{targetPayee}</span>
                      </div>
                    </div>
                  </div>

                  {/* Submission Form (UTR & Screenshot) */}
                  <form onSubmit={handleUpiSubmit} className="mt-6 pt-5 border-t border-slate-800 space-y-4">
                    <h5 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-cyan-400" />
                      <span>Step 2: Enter Verification Details</span>
                    </h5>

                    <div>
                      <label className="text-xs font-medium text-slate-300 block mb-1">
                        12-Digit UPI Reference Number (UTR / Ref ID) <span className="text-rose-400">*</span>
                      </label>
                      <input
                        type="text"
                        required
                        placeholder="e.g. 423589123456"
                        value={upiRefNo}
                        onChange={(e) => setUpiRefNo(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs font-mono text-white placeholder-slate-600 focus:border-cyan-400 outline-none transition-colors"
                      />
                      <p className="text-[11px] text-slate-500 mt-1">
                        Found in your UPI app receipt under "UPI Ref No." or "UTR".
                      </p>
                    </div>

                    <div>
                      <label className="text-xs font-medium text-slate-300 block mb-1">
                        Payment Screenshot / Receipt <span className="text-rose-400">*</span>
                      </label>
                      <label className="relative flex flex-col items-center justify-center p-4 border border-dashed border-slate-700 hover:border-cyan-500/50 rounded-xl cursor-pointer bg-slate-950/60 hover:bg-slate-900/40 transition-colors">
                        <input
                          type="file"
                          accept="image/png,image/jpeg,image/webp"
                          onChange={handleFileChange}
                          className="sr-only"
                        />
                        {receiptPreview ? (
                          <div className="flex items-center gap-3">
                            <img
                              src={receiptPreview}
                              alt="Receipt preview"
                              className="w-12 h-12 object-cover rounded-lg border border-slate-700"
                            />
                            <div className="text-left text-xs">
                              <span className="text-white font-medium block truncate max-w-xs">
                                {receiptFile?.name}
                              </span>
                              <span className="text-emerald-400 text-[11px]">Click to change image</span>
                            </div>
                          </div>
                        ) : (
                          <div className="text-center">
                            <Upload className="w-6 h-6 text-cyan-400 mx-auto mb-1.5" />
                            <span className="text-xs text-slate-300 font-medium block">
                              Upload Payment Screenshot
                            </span>
                            <span className="text-[11px] text-slate-500">PNG, JPG, or WEBP up to 5MB</span>
                          </div>
                        )}
                      </label>
                    </div>

                    <div className="p-3 rounded-xl border border-amber-500/20 bg-amber-950/20 text-[11px] text-amber-300/90 leading-relaxed flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <span>
                        <strong>Security Notice:</strong> To ensure platform integrity and prevent fraud, all manual UPI transactions undergo SOC Admin review before membership activation. Never make duplicate payments.
                      </span>
                    </div>

                    <div className="flex justify-end gap-3 pt-2">
                      <button
                        type="button"
                        onClick={onClose}
                        className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white transition-colors"
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        disabled={isSubmitting || !upiRefNo || !receiptFile}
                        className="px-6 py-2.5 rounded-xl text-xs font-bold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all flex items-center gap-2"
                      >
                        {isSubmitting ? (
                          <>
                            <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                            <span>Submitting Verification...</span>
                          </>
                        ) : (
                          <>
                            <ShieldCheck className="w-4 h-4" />
                            <span>Submit Payment Proof</span>
                          </>
                        )}
                      </button>
                    </div>
                  </form>
                </div>
              ) : (
                /* Method B: Razorpay / Gateway */
                <div className="text-center py-8">
                  <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mx-auto mb-4">
                    <CreditCard className="w-7 h-7" />
                  </div>
                  <h4 className="text-base font-bold text-white mb-2">Online Gateway Integration</h4>
                  <p className="text-xs text-slate-400 max-w-md mx-auto mb-6 leading-relaxed">
                    Razorpay Gateway enables instant credit/debit card, netbanking, and authorized merchant settlement with HMAC-SHA256 signature verification.
                  </p>

                  <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 max-w-sm mx-auto mb-6 text-left text-xs space-y-2">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Order Token:</span>
                      <span className="font-mono text-cyan-300 font-bold">{createdOrder?.order_code || 'Pending'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Payable:</span>
                      <span className="font-mono text-white font-bold">₹{plan.price_inr}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Security:</span>
                      <span className="text-emerald-400 font-semibold">256-Bit TLS + Server Signature</span>
                    </div>
                  </div>

                  <button
                    onClick={() => {
                      alert('Razorpay Checkout: In sandbox mode, please switch to UPI QR for direct admin queue submission or set RAZORPAY_KEY_ID in server environment.');
                    }}
                    className="px-6 py-3 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all inline-flex items-center gap-2"
                  >
                    <span>Proceed to Razorpay Checkout</span>
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PaymentCheckoutModal;
