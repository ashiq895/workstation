import express, { Request, Response, NextFunction } from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  registerOrUpdateSession,
  updateHeartbeat,
  logActivity,
  saveUploadedImage,
  saveMonitoringReport,
  saveDailyReport,
  getOverviewStats,
  getActiveUsers,
  getAllSessions,
  getAllActivities,
  getAllUploads,
  getUploadFilePath,
  getAllReports,
  createAdminToken,
  verifyAdminToken,
  clearAllData,
  lookupGeo
} from './server/db.ts';
import { parseUserAgent } from './src/utils/detector.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// Body parsers with high limits to accept image uploads
app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true, limit: '60mb' }));

// Helper to extract IP
function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    const first = forwarded.split(',')[0].trim();
    if (first) return first.replace(/^::ffff:/, '');
  }
  const remote = req.socket.remoteAddress || '127.0.0.1';
  return remote.replace(/^::ffff:/, '');
}

// Admin auth middleware
function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '') || (req.headers['x-admin-token'] as string);
  if (!token || !verifyAdminToken(token)) {
    res.status(401).json({ error: 'Unauthorized: Invalid or expired admin session' });
    return;
  }
  next();
}

// ---------------- TELEMETRY API ---------------- //

// Register or update visitor session
app.post('/api/telemetry/session', async (req: Request, res: Response) => {
  try {
    const { sessionId, screen, language, referrer, currentTab } = req.body;
    if (!sessionId) {
      res.status(400).json({ error: 'sessionId is required' });
      return;
    }

    const ip = getClientIp(req);
    const ua = req.headers['user-agent'] || '';
    const parsed = parseUserAgent(ua);
    const geo = await lookupGeo(ip);

    const device = {
      type: parsed.type,
      os: parsed.os,
      browser: parsed.browser,
      userAgent: ua,
      screen: screen || 'Unknown',
      language: language || 'en',
      referrer: referrer || 'Direct'
    };

    const session = registerOrUpdateSession(sessionId, ip, device, geo, currentTab);
    logActivity(sessionId, ip, 'visit', `Visitor opened website (${parsed.browser} on ${parsed.os})`, {
      device: parsed.type,
      ip,
      location: `${geo.city || 'Unknown'}, ${geo.country || 'Unknown'}`
    });

    res.json({ success: true, session });
  } catch (err: any) {
    console.error('Error in /api/telemetry/session:', err);
    res.status(500).json({ error: err.message });
  }
});

// Heartbeat to maintain active user status
app.post('/api/telemetry/heartbeat', (req: Request, res: Response) => {
  const { sessionId, currentTab } = req.body;
  if (!sessionId) {
    res.status(400).json({ error: 'sessionId is required' });
    return;
  }
  const updated = updateHeartbeat(sessionId, currentTab);
  res.json({ ok: updated });
});

// General activity logging
app.post('/api/telemetry/activity', (req: Request, res: Response) => {
  const { sessionId, type, label, details } = req.body;
  const ip = getClientIp(req);
  if (!sessionId) {
    res.status(400).json({ error: 'sessionId is required' });
    return;
  }
  const log = logActivity(sessionId, ip, type || 'action', label || 'User Action', details);
  res.json({ ok: true, id: log.id });
});

// Image Cleaner Upload
app.post('/api/telemetry/upload', (req: Request, res: Response) => {
  try {
    const {
      sessionId,
      fileName,
      cleanFileName,
      fileType,
      originalSize,
      cleanedSize,
      removedMetadata,
      hasGPS,
      dimensions,
      thumbnailBase64,
      fileBase64
    } = req.body;

    const ip = getClientIp(req);
    const record = saveUploadedImage(
      {
        sessionId: sessionId || 'anon',
        ip,
        fileName: fileName || 'unnamed-image',
        cleanFileName: cleanFileName || 'cleaned-image',
        fileType: fileType || 'image/jpeg',
        originalSize: originalSize || 0,
        cleanedSize: cleanedSize || 0,
        removedMetadata: removedMetadata || [],
        hasGPS: Boolean(hasGPS),
        dimensions: dimensions || '',
        thumbnailBase64
      },
      fileBase64
    );

    res.json({ ok: true, id: record.id });
  } catch (err: any) {
    console.error('Error saving upload:', err);
    res.status(500).json({ error: err.message });
  }
});

// Reports Logging (Monitoring & Daily Reports)
app.post('/api/telemetry/report', (req: Request, res: Response) => {
  try {
    const { type, sessionId, ...data } = req.body;
    const ip = getClientIp(req);

    if (type === 'monitoring') {
      const saved = saveMonitoringReport({
        sessionId: sessionId || 'anon',
        ip,
        heading1: data.heading1 || '',
        heading2: data.heading2 || '',
        newsHeading: data.newsHeading || '',
        items: data.items || [],
        action: data.action || 'added'
      });
      res.json({ ok: true, id: saved.id });
      return;
    }

    if (type === 'daily') {
      const saved = saveDailyReport({
        sessionId: sessionId || 'anon',
        ip,
        subject: data.subject || '',
        branch: data.branch || '',
        date: data.date || '',
        counts: data.counts || [],
        fullText: data.fullText || '',
        action: data.action || 'saved'
      });
      res.json({ ok: true, id: saved.id });
      return;
    }

    res.status(400).json({ error: 'Unknown report type' });
  } catch (err: any) {
    console.error('Error logging report:', err);
    res.status(500).json({ error: err.message });
  }
});

// ---------------- ADMIN API ---------------- //

// Admin Login
// Requested credentials: username "ashiq", password "24862500"
app.post('/api/admin/login', (req: Request, res: Response) => {
  const { username, password } = req.body;
  const ip = getClientIp(req);

  if (username === 'ashiq' && password === '24862500') {
    const token = createAdminToken();
    logActivity('admin_panel', ip, 'admin_login_success', 'Admin logged in successfully', { username });
    res.json({ success: true, token, user: 'ashiq' });
  } else {
    logActivity('admin_panel', ip, 'admin_login_failed', `Failed admin login attempt with username: ${username}`, {
      username
    });
    res.status(401).json({ success: false, error: 'ভুল ইউজারনেম বা পাসওয়ার্ড (Invalid Username or Password)' });
  }
});

// Admin Overview
app.get('/api/admin/overview', requireAdmin, (_req: Request, res: Response) => {
  const stats = getOverviewStats();
  res.json(stats);
});

// Admin Active Users
app.get('/api/admin/active-users', requireAdmin, (_req: Request, res: Response) => {
  const active = getActiveUsers();
  res.json(active);
});

// Admin All Sessions / Visitors
app.get('/api/admin/sessions', requireAdmin, (_req: Request, res: Response) => {
  const sessions = getAllSessions();
  res.json(sessions);
});

// Admin Activity stream
app.get('/api/admin/activities', requireAdmin, (req: Request, res: Response) => {
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 150;
  const activities = getAllActivities(limit);
  res.json(activities);
});

// Admin Uploaded Images Vault
app.get('/api/admin/uploads', requireAdmin, (_req: Request, res: Response) => {
  const uploads = getAllUploads();
  res.json(uploads);
});

// Download/View full uploaded image
app.get('/api/admin/uploads/:id/file', requireAdmin, (req: Request, res: Response) => {
  const uploads = getAllUploads();
  const item = uploads.find(u => u.id === req.params.id);
  if (!item || !item.filePath) {
    res.status(404).send('File not found');
    return;
  }
  const filePath = getUploadFilePath(item.filePath);
  if (fs.existsSync(filePath)) {
    res.setHeader('Content-Type', item.fileType);
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(item.fileName)}"`);
    fs.createReadStream(filePath).pipe(res);
  } else {
    res.status(404).send('File content missing from disk');
  }
});

// Admin Reports (Monitoring + Daily)
app.get('/api/admin/reports', requireAdmin, (_req: Request, res: Response) => {
  const reports = getAllReports();
  res.json(reports);
});

// Clear logs
app.post('/api/admin/clear-logs', requireAdmin, (_req: Request, res: Response) => {
  clearAllData();
  res.json({ success: true, message: 'All logs cleared' });
});

// ---------------- FRONTEND INTEGRATION ---------------- //

async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    // In dev mode, mount Vite middleware as recommended by AI Studio instructions
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    // Production static serving
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Workstation & Admin Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
