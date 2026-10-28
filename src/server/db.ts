/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import crypto from 'crypto';
import { QRCodeRecord, ScanRecord, QRAnalytics, DashboardStats, QRStyle, DeviceCategory } from '../types.js';

interface UserRecord {
  id: string;
  email: string;
  password_hash: string;
  name: string;
  reset_token?: string | null;
  reset_token_expires_at?: string | null;
  created_at: string;
}

// In-Memory DB Stores (AI Studio Container Environment)
const usersStore = new Map<string, UserRecord>();
const qrStore = new Map<string, QRCodeRecord>();
const scansStore: ScanRecord[] = [];

// Dummy export db object for backwards compatibility
export const db = {
  prepare: () => ({
    get: () => null,
    all: () => [],
    run: () => ({ changes: 0 }),
  }),
};

// Password Hashing
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  try {
    const [salt, key] = storedHash.split(':');
    if (!salt || !key) return false;
    const testHash = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(key, 'hex'), Buffer.from(testHash, 'hex'));
  } catch {
    return false;
  }
}

// Generate random URL-safe alphanumeric code
export function generateRandomCode(length = 7): string {
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789ABCDEFGHJKMNPQRSTUVWXYZ';
  let result = '';
  const randomBytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    result += chars[randomBytes[i] % chars.length];
  }
  return result;
}

// User Management
export function findUserByEmail(email: string): UserRecord | undefined {
  const target = email.trim().toLowerCase();
  for (const u of usersStore.values()) {
    if (u.email.toLowerCase() === target) {
      return u;
    }
  }
  return undefined;
}

export function getUserById(id: string): { id: string; email: string; name: string; created_at: string } | undefined {
  const user = usersStore.get(id);
  if (!user) return undefined;
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    created_at: user.created_at,
  };
}

export function createUser(email: string, passwordPlain: string, name: string) {
  const id = crypto.randomUUID();
  const password_hash = hashPassword(passwordPlain);
  const user: UserRecord = {
    id,
    email: email.trim().toLowerCase(),
    password_hash,
    name: name.trim(),
    created_at: new Date().toISOString(),
  };
  usersStore.set(id, user);
  return getUserById(id)!;
}

export function createPasswordResetToken(email: string): string | null {
  const user = findUserByEmail(email);
  if (!user) return null;
  const token = crypto.randomBytes(24).toString('hex');
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60).toISOString();
  user.reset_token = token;
  user.reset_token_expires_at = expiresAt;
  return token;
}

export function resetPasswordWithToken(token: string, newPasswordPlain: string): boolean {
  const now = new Date().toISOString();
  for (const user of usersStore.values()) {
    if (user.reset_token === token && user.reset_token_expires_at && user.reset_token_expires_at > now) {
      user.password_hash = hashPassword(newPasswordPlain);
      user.reset_token = null;
      user.reset_token_expires_at = null;
      return true;
    }
  }
  return false;
}

export function ensureUserExists(userId: string, name = 'Free Workspace') {
  if (!usersStore.has(userId)) {
    usersStore.set(userId, {
      id: userId,
      email: `${userId.toLowerCase()}@fluxqr.local`,
      password_hash: '',
      name,
      created_at: new Date().toISOString(),
    });
  }
}

// Device detection helper
export function parseDeviceCategory(userAgent: string | undefined): {
  device: DeviceCategory;
  browser: string;
  os: string;
} {
  if (!userAgent) {
    return { device: 'unknown', browser: 'Unknown', os: 'Unknown' };
  }

  const ua = userAgent.toLowerCase();

  if (ua.includes('bot') || ua.includes('crawl') || ua.includes('spider') || ua.includes('slurp') || ua.includes('mediapartners')) {
    return { device: 'bot', browser: 'Bot Crawler', os: 'Server' };
  }

  let device: DeviceCategory = 'desktop';
  if (ua.includes('ipad') || (ua.includes('tablet') && !ua.includes('mobile')) || (ua.includes('android') && !ua.includes('mobile'))) {
    device = 'tablet';
  } else if (ua.includes('mobile') || ua.includes('iphone') || ua.includes('ipod') || ua.includes('android')) {
    device = 'mobile';
  }

  let browser = 'Other';
  if (ua.includes('edg/')) browser = 'Edge';
  else if (ua.includes('chrome/')) browser = 'Chrome';
  else if (ua.includes('safari/') && !ua.includes('chrome/')) browser = 'Safari';
  else if (ua.includes('firefox/')) browser = 'Firefox';
  else if (ua.includes('opera/') || ua.includes('opr/')) browser = 'Opera';

  let os = 'Other';
  if (ua.includes('windows')) os = 'Windows';
  else if (ua.includes('macintosh') || ua.includes('mac os')) os = 'macOS';
  else if (ua.includes('iphone') || ua.includes('ipad')) os = 'iOS';
  else if (ua.includes('android')) os = 'Android';
  else if (ua.includes('linux')) os = 'Linux';

  return { device, browser, os };
}

// QR Code Queries
export function listUserQRCodes(
  userId: string,
  options: { search?: string; status?: string; sortBy?: string; sortOrder?: 'asc' | 'desc' } = {}
): QRCodeRecord[] {
  const isPublicUser = userId === 'public_free_user';
  let qrs = Array.from(qrStore.values()).filter((q) => {
    if (isPublicUser) {
      return q.user_id === userId || q.user_id === 'usr_demo_founder_2026';
    }
    return q.user_id === userId;
  });

  if (options.status && (options.status === 'active' || options.status === 'paused')) {
    qrs = qrs.filter((q) => q.status === options.status);
  }

  if (options.search && options.search.trim()) {
    const s = options.search.trim().toLowerCase();
    qrs = qrs.filter(
      (q) =>
        q.name.toLowerCase().includes(s) ||
        q.destination_url.toLowerCase().includes(s) ||
        (q.description && q.description.toLowerCase().includes(s)) ||
        q.code.toLowerCase().includes(s)
    );
  }

  // Attach scan count
  const result: QRCodeRecord[] = qrs.map((q) => {
    const scanCount = scansStore.filter((s) => s.qr_code_id === q.id).length;
    return { ...q, scan_count: scanCount };
  });

  // Sorting
  const sortDir = options.sortOrder === 'asc' ? 1 : -1;
  result.sort((a, b) => {
    if (options.sortBy === 'name') {
      return a.name.localeCompare(b.name) * sortDir;
    }
    if (options.sortBy === 'scans') {
      return ((a.scan_count || 0) - (b.scan_count || 0)) * sortDir;
    }
    if (options.sortBy === 'updated') {
      return (new Date(a.updated_at).getTime() - new Date(b.updated_at).getTime()) * sortDir;
    }
    return (new Date(a.created_at).getTime() - new Date(b.created_at).getTime()) * sortDir;
  });

  return result;
}

export function getQRById(id: string, userId?: string): QRCodeRecord | null {
  const qr = qrStore.get(id);
  if (!qr) return null;

  if (userId) {
    if (userId === 'public_free_user') {
      if (qr.user_id !== userId && qr.user_id !== 'usr_demo_founder_2026') return null;
    } else if (qr.user_id !== userId) {
      return null;
    }
  }

  const scanCount = scansStore.filter((s) => s.qr_code_id === qr.id).length;
  return { ...qr, scan_count: scanCount };
}

export function getQRByCode(code: string): QRCodeRecord | null {
  for (const q of qrStore.values()) {
    if (q.code === code) {
      const scanCount = scansStore.filter((s) => s.qr_code_id === q.id).length;
      return { ...q, scan_count: scanCount };
    }
  }
  return null;
}

export function createQRCode(data: {
  user_id: string;
  name: string;
  description?: string;
  destination_url: string;
  qr_style?: QRStyle;
}): QRCodeRecord {
  const id = crypto.randomUUID();

  let code = generateRandomCode(7);
  let attempts = 0;
  while (attempts < 10) {
    if (!getQRByCode(code)) break;
    code = generateRandomCode(8);
    attempts++;
  }

  const defaultStyle: QRStyle = {
    fgColor: '#0f172a',
    bgColor: '#ffffff',
    size: 512,
    errorCorrection: 'M',
    dotStyle: 'square',
    ...data.qr_style,
  };

  const now = new Date().toISOString();
  const record: QRCodeRecord = {
    id,
    user_id: data.user_id,
    code,
    name: data.name.trim(),
    description: data.description ? data.description.trim() : null,
    destination_url: data.destination_url.trim(),
    status: 'active',
    qr_style: defaultStyle,
    scan_count: 0,
    created_at: now,
    updated_at: now,
  };

  qrStore.set(id, record);
  return record;
}

export function updateQRCode(
  id: string,
  userId: string,
  updates: {
    name?: string;
    description?: string;
    destination_url?: string;
    status?: 'active' | 'paused';
    qr_style?: Partial<QRStyle>;
  }
): QRCodeRecord | null {
  const existing = getQRById(id, userId);
  if (!existing) return null;

  const newName = updates.name !== undefined ? updates.name.trim() : existing.name;
  const newDesc = updates.description !== undefined ? updates.description.trim() : existing.description;
  const newDest = updates.destination_url !== undefined ? updates.destination_url.trim() : existing.destination_url;
  const newStatus = updates.status !== undefined ? updates.status : existing.status;
  const newStyle = updates.qr_style ? { ...existing.qr_style, ...updates.qr_style } : existing.qr_style;

  const updatedRecord: QRCodeRecord = {
    ...existing,
    name: newName,
    description: newDesc,
    destination_url: newDest,
    status: newStatus,
    qr_style: newStyle,
    updated_at: new Date().toISOString(),
  };

  qrStore.set(id, updatedRecord);
  return getQRById(id, userId);
}

export function toggleQRStatus(id: string, userId: string, status: 'active' | 'paused'): QRCodeRecord | null {
  return updateQRCode(id, userId, { status });
}

export function deleteQRCode(id: string, userId: string): boolean {
  const existing = getQRById(id, userId);
  if (!existing) return false;
  qrStore.delete(id);
  return true;
}

// Record scan analytics
export function recordScan(data: {
  qr_code_id: string;
  referrer?: string;
  userAgent?: string;
  ip?: string;
}): boolean {
  try {
    const id = crypto.randomUUID();
    const { device, browser, os } = parseDeviceCategory(data.userAgent);

    let ip_hash: string | undefined = undefined;
    if (data.ip) {
      const todaySalt = new Date().toISOString().slice(0, 10) + '_flux_salt';
      ip_hash = crypto.createHash('sha256').update(data.ip + todaySalt).digest('hex').substring(0, 20);
    }

    const cleanRef = data.referrer ? data.referrer.slice(0, 255) : null;

    scansStore.push({
      id,
      qr_code_id: data.qr_code_id,
      scanned_at: new Date().toISOString(),
      referrer: cleanRef,
      device_category: device,
      browser,
      os,
      ip_hash,
    });
    return true;
  } catch (err) {
    console.error('Non-blocking analytics recording warning:', err);
    return false;
  }
}

// Analytics Aggregation
export function getQRAnalytics(qr_code_id: string, user_id: string): QRAnalytics | null {
  const qr = getQRById(qr_code_id, user_id);
  if (!qr) return null;

  const qrScans = scansStore.filter((s) => s.qr_code_id === qr_code_id);
  const total = qrScans.length;

  const uniqueIps = new Set(qrScans.map((s) => s.ip_hash).filter(Boolean));
  const uniqueEst = uniqueIps.size > 0 ? uniqueIps.size : Math.min(total, Math.ceil(total * 0.75));

  // Scans by day (last 14 days)
  const daysMap = new Map<string, number>();
  const now = new Date();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().slice(0, 10);
    daysMap.set(dateStr, 0);
  }

  for (const s of qrScans) {
    const dateStr = s.scanned_at.slice(0, 10);
    if (daysMap.has(dateStr)) {
      daysMap.set(dateStr, (daysMap.get(dateStr) || 0) + 1);
    }
  }

  const scans_by_day = Array.from(daysMap.entries()).map(([date, count]) => ({ date, count }));

  // Devices breakdown
  const devCounts = new Map<string, number>();
  for (const s of qrScans) {
    const dev = s.device_category || 'unknown';
    devCounts.set(dev, (devCounts.get(dev) || 0) + 1);
  }
  const devices = Array.from(devCounts.entries()).map(([name, count]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    count,
    percentage: total > 0 ? Math.round((count / total) * 100) : 0,
  }));

  // Referrers breakdown
  const refCounts = new Map<string, number>();
  for (const s of qrScans) {
    let refName = 'Direct / QR Camera';
    const r = s.referrer ? s.referrer.toLowerCase() : '';
    if (r.includes('google')) refName = 'Google';
    else if (r.includes('twitter') || r.includes('t.co') || r.includes('x.com')) refName = 'X / Twitter';
    else if (r.includes('linkedin')) refName = 'LinkedIn';
    else if (r.includes('facebook') || r.includes('fb')) refName = 'Facebook';
    else if (r.includes('instagram')) refName = 'Instagram';
    else if (r) refName = 'Other Website';

    refCounts.set(refName, (refCounts.get(refName) || 0) + 1);
  }

  const referrers = Array.from(refCounts.entries())
    .map(([name, count]) => ({
      name,
      count,
      percentage: total > 0 ? Math.round((count / total) * 100) : 0,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const recent_scans = [...qrScans]
    .sort((a, b) => new Date(b.scanned_at).getTime() - new Date(a.scanned_at).getTime())
    .slice(0, 20);

  return {
    qr_id: qr_code_id,
    total_scans: total,
    unique_scans_estimate: uniqueEst,
    scans_by_day,
    devices,
    referrers,
    recent_scans,
  };
}

// User Dashboard Overall Stats
export function getDashboardStats(userId: string): DashboardStats {
  const userQRs = listUserQRCodes(userId);
  const total_qrs = userQRs.length;
  const active_qrs = userQRs.filter((q) => q.status === 'active').length;
  const paused_qrs = userQRs.filter((q) => q.status === 'paused').length;

  const qrIds = new Set(userQRs.map((q) => q.id));
  const userScans = scansStore.filter((s) => qrIds.has(s.qr_code_id));
  const total_scans = userScans.length;

  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const scans_last_7_days = userScans.filter((s) => s.scanned_at >= sevenDaysAgo).length;

  return {
    total_qrs,
    active_qrs,
    paused_qrs,
    total_scans,
    scans_last_7_days,
  };
}

// Seed Database
function seedDatabase() {
  ensureUserExists('public_free_user', 'Public Free Workspace');

  // Seed initial demo QRs for instant workspace preview
  const demoQRs = [
    {
      id: 'qr_demo_spring_launch',
      user_id: 'public_free_user',
      code: 'spring26',
      name: 'Spring Marketing Launch',
      description: 'Dynamic print flyer QR code for 2026 Spring campaign promotion',
      destination_url: 'https://example.com/spring-launch',
      status: 'active' as const,
      qr_style: {
        fgColor: '#0f172a',
        bgColor: '#ffffff',
        size: 512,
        errorCorrection: 'M' as const,
        dotStyle: 'square' as const,
      },
      created_at: new Date(Date.now() - 12 * 24 * 3600 * 1000).toISOString(),
      updated_at: new Date(Date.now() - 2 * 24 * 3600 * 1000).toISOString(),
    },
    {
      id: 'qr_demo_summit_pass',
      user_id: 'public_free_user',
      code: 'summit26',
      name: 'Tech Summit VIP Badge',
      description: 'Conference attendee badge QR linking to digital schedule',
      destination_url: 'https://example.com/tech-summit-schedule',
      status: 'active' as const,
      qr_style: {
        fgColor: '#2563eb',
        bgColor: '#f8fafc',
        size: 512,
        errorCorrection: 'Q' as const,
        dotStyle: 'dots' as const,
      },
      created_at: new Date(Date.now() - 8 * 24 * 3600 * 1000).toISOString(),
      updated_at: new Date(Date.now() - 1 * 24 * 3600 * 1000).toISOString(),
    },
    {
      id: 'qr_demo_product_box',
      user_id: 'public_free_user',
      code: 'manual26',
      name: 'Product Box Insert - User Manual',
      description: 'Physical packaging insert linking to live PDF documentation',
      destination_url: 'https://example.com/docs/manual-v2.pdf',
      status: 'paused' as const,
      qr_style: {
        fgColor: '#475569',
        bgColor: '#ffffff',
        size: 512,
        errorCorrection: 'L' as const,
        dotStyle: 'rounded' as const,
      },
      created_at: new Date(Date.now() - 20 * 24 * 3600 * 1000).toISOString(),
      updated_at: new Date(Date.now() - 5 * 24 * 3600 * 1000).toISOString(),
    },
  ];

  for (const q of demoQRs) {
    if (!qrStore.has(q.id)) {
      qrStore.set(q.id, { ...q, scan_count: 0 });
    }
  }

  // Seed sample scans for analytics preview
  if (scansStore.length === 0) {
    const devicesList: DeviceCategory[] = ['mobile', 'mobile', 'mobile', 'desktop', 'tablet'];
    const browsers = ['Chrome', 'Safari', 'Firefox', 'Edge'];
    const osList = ['iOS', 'Android', 'macOS', 'Windows'];
    const referrers = ['', 'https://google.com', 'https://t.co/abc', 'https://linkedin.com', ''];

    const qrIds = ['qr_demo_spring_launch', 'qr_demo_summit_pass', 'qr_demo_product_box'];
    const now = Date.now();

    for (let i = 0; i < 48; i++) {
      const randomDaysAgo = Math.random() * 12;
      const scannedAt = new Date(now - randomDaysAgo * 24 * 3600 * 1000).toISOString();
      const qrId = qrIds[i % qrIds.length];
      const dev = devicesList[i % devicesList.length];

      scansStore.push({
        id: crypto.randomUUID(),
        qr_code_id: qrId,
        scanned_at: scannedAt,
        referrer: referrers[i % referrers.length] || null,
        device_category: dev,
        browser: browsers[i % browsers.length],
        os: osList[i % osList.length],
        ip_hash: `ip_hash_${i % 15}`,
      });
    }
  }
}

seedDatabase();

export default db;
