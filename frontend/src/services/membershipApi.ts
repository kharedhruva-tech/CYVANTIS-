import { API_BASE_URL, getAuthToken, apiRequest } from './api';

export interface MembershipPlan {
  id: number;
  code: string;
  name: string;
  description: string;
  price_inr: number;
  duration_days: number;
  tier: 'free' | 'premium';
  badge?: string;
  daily_scan_limit: number;
  features: string[];
  is_active: boolean;
  sort_order: number;
}

export interface PaymentOrder {
  id: number;
  order_code: string;
  user_id: number;
  plan_id: number;
  payment_method: 'upi_qr' | 'razorpay';
  amount_inr: number;
  status: 'pending' | 'approved' | 'rejected' | 'failed';
  upi_ref_no?: string;
  receipt_screenshot_url?: string;
  gateway_order_id?: string;
  gateway_payment_id?: string;
  gateway_signature?: string;
  admin_notes?: string;
  verified_by_id?: number;
  verified_at?: string;
  created_at: string;
  plan_name?: string;
  plan_code?: string;
  username?: string;
  user_email?: string;
}

export interface UserSubscription {
  plan_code: string;
  plan_name: string;
  tier: 'free' | 'premium';
  status: 'active' | 'expired' | 'revoked' | 'none';
  start_date?: string;
  end_date?: string;
  days_remaining?: number | null;
  daily_scan_limit: number;
  is_premium: boolean;
  features: string[];
  pending_order?: PaymentOrder | null;
}

export interface UpiConfig {
  id: number;
  upi_id: string;
  account_name: string;
  merchant_code?: string;
  qr_image_url?: string;
  instructions: string;
  is_active: boolean;
}

export interface AdminMembershipOverview {
  total_users: number;
  active_premium_users: number;
  pending_verifications: number;
  approved_orders: number;
  rejected_orders: number;
  total_revenue_inr: number;
}

export interface PaymentAuditLog {
  id: number;
  order_id?: number;
  user_id?: number;
  action: string;
  details?: Record<string, any>;
  performed_by_name?: string;
  ip_address?: string;
  created_at: string;
}

export const membershipApi = {
  // Public & User actions
  getPlans: async (): Promise<MembershipPlan[]> => {
    return apiRequest<MembershipPlan[]>('/memberships/plans');
  },

  getMySubscription: async (): Promise<UserSubscription> => {
    return apiRequest<UserSubscription>('/memberships/my-subscription');
  },

  getUpiConfig: async (): Promise<UpiConfig> => {
    return apiRequest<UpiConfig>('/memberships/upi-config');
  },

  createOrder: async (plan_id: number, payment_method: 'upi_qr' | 'razorpay' = 'upi_qr'): Promise<PaymentOrder> => {
    return apiRequest<PaymentOrder>('/memberships/orders/create', {
      method: 'POST',
      body: JSON.stringify({ plan_id, payment_method })
    });
  },

  submitUpiPayment: async (
    orderCode: string,
    upiRefNo: string,
    screenshotFile: File
  ): Promise<PaymentOrder> => {
    const token = getAuthToken();
    const formData = new FormData();
    formData.append('upi_ref_no', upiRefNo.trim());
    formData.append('screenshot', screenshotFile);

    const headers: Record<string, string> = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE_URL}/memberships/orders/${orderCode}/submit-upi`, {
      method: 'POST',
      headers,
      body: formData
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'Failed to upload proof' }));
      throw new Error(err.detail || 'Payment proof submission failed');
    }

    return response.json();
  },

  verifyRazorpayPayment: async (payload: {
    order_code: string;
    razorpay_payment_id: string;
    razorpay_order_id: string;
    razorpay_signature: string;
  }): Promise<PaymentOrder> => {
    return apiRequest<PaymentOrder>('/memberships/orders/verify-razorpay', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  getOrderHistory: async (): Promise<PaymentOrder[]> => {
    return apiRequest<PaymentOrder[]>('/memberships/orders/history');
  },

  // Admin Actions
  getAdminOverview: async (): Promise<AdminMembershipOverview> => {
    return apiRequest<AdminMembershipOverview>('/memberships/admin/overview');
  },

  getAdminOrders: async (statusFilter?: string): Promise<PaymentOrder[]> => {
    const q = statusFilter ? `?status_filter=${encodeURIComponent(statusFilter)}` : '';
    return apiRequest<PaymentOrder[]>(`/memberships/admin/orders${q}`);
  },

  verifyAdminOrder: async (
    orderId: number,
    action: 'approved' | 'rejected',
    admin_notes?: string
  ): Promise<PaymentOrder> => {
    return apiRequest<PaymentOrder>(`/memberships/admin/orders/${orderId}/verify`, {
      method: 'POST',
      body: JSON.stringify({ action, admin_notes })
    });
  },

  manualActivate: async (payload: {
    user_id: number;
    plan_code: string;
    duration_days?: number;
    notes?: string;
  }): Promise<{ message: string; end_date: string }> => {
    return apiRequest<{ message: string; end_date: string }>('/memberships/admin/manual-activate', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  getAdminPlans: async (): Promise<MembershipPlan[]> => {
    return apiRequest<MembershipPlan[]>('/memberships/admin/plans');
  },

  updateAdminPlan: async (planId: number, data: Partial<MembershipPlan>): Promise<MembershipPlan> => {
    return apiRequest<MembershipPlan>(`/memberships/admin/plans/${planId}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  },

  getAdminUpiConfig: async (): Promise<UpiConfig> => {
    return apiRequest<UpiConfig>('/memberships/admin/upi-config');
  },

  updateAdminUpiConfig: async (data: Partial<UpiConfig>): Promise<UpiConfig> => {
    return apiRequest<UpiConfig>('/memberships/admin/upi-config', {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  },

  getAdminAuditLogs: async (limit: number = 100): Promise<PaymentAuditLog[]> => {
    return apiRequest<PaymentAuditLog[]>(`/memberships/admin/audit-logs?limit=${limit}`);
  },

  getReceiptUrl: (filename: string): string => {
    const token = getAuthToken();
    const clean = filename.replace(/^.*[\\\/]/, '');
    return `${API_BASE_URL}/memberships/receipts/${clean}${token ? `?token=${encodeURIComponent(token)}` : ''}`;
  }
};
