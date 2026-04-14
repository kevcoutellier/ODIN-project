/**
 * Odin Dashboard Server v2.0
 * 3-column layout: Sidebar + Main + Alerts Panel
 * 5 sections: Home / Cron / Activity / System / Security
 * Inspired by Claw Dash + AEGIS security layers
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface DashboardState {
  // Identity
  agentName: string;
  did: string;
  trustMode: 'SAFE' | 'CAUTION' | 'DEGRADED';
  gatewayStatus: 'connected' | 'offline';
  uptime: string;
  llmModel: string;
  llmProvider: string;
  llmMaxTokens: number;
  llmTemperature: number;

  // KPIs
  trustScore: number;
  trustScoreDelta: number;
  skillsInstalled: number;
  skillsTier1Plus: number;
  skillsTier0: number;
  agentsConnected: number;
  agentsCertified: number;
  agentsMonitoring: number;
  alertsActive: number;
  alertsCritical: number;
  alertsWarning: number;
  activeSessions: number;
  tokensToday: number;
  channels: number;

  // Trust Score 6 dimensions
  dimensions: {
    performance: number;
    transparency: number;
    security: number;
    compliance: number;
    reputation: number;
    reliability: number;
  };
  trustHistory: Array<{ date: string; score: number }>;
  nextEvaluation: string;
  certifiedBy: string;

  // AEGIS layers
  aegisLayers: Array<{
    name: string;
    description: string;
    status: 'ACTIF' | 'ALERTE' | 'INACTIF';
    metric: string;
    owaspRisks: string[];
  }>;
  circuitBreakerState: 'CLOSED' | 'DEGRADED' | 'OPEN' | 'HALF_OPEN';
  circuitBreakerMetrics: { totalCalls: number; failures: number; semanticFailures: number };

  // Skills, Agents, MCP
  skills: Array<{ name: string; version: string; tier: 0 | 1 | 2; ring: 0 | 1 | 2; score: number | null; status: string }>;
  peerAgents: Array<{ name: string; did: string; trustScore: number; status: 'trusted' | 'monitoring' | 'quarantined' }>;
  mcpServers: Array<{ name: string; url: string; score: number; status: 'SAFE' | 'CAUTION' | 'DANGEROUS' }>;

  // Decision Trace + Alerts
  decisionTrace: Array<{ timestamp: string; type: 'allow' | 'warn' | 'block'; emitter: string; action: string; detail: string; layer: string }>;
  alerts: Array<{ id: string; timestamp: string; severity: 'critical' | 'warn' | 'info'; source: string; message: string; acknowledged: boolean }>;

  // Activity
  activities: Array<{ timestamp: string; type: 'tool_call' | 'chat' | 'a2a' | 'security' | 'cognition'; action: string; detail: string; tokens?: number; duration?: string }>;

  // Compliance + Perf
  compliance: { euAiAct: number; owaspAsi: string; singaporeMgf: number; slsa: number };
  performance: { latencyMs: number; taskCompletion: number; tokenOverhead: number; merkleVerifyMs: number };

  // Recent chats
  recentChats: Array<{ id: string; title: string; timestamp: string }>;
}

export type ChatHandler = (message: string) => Promise<string>;
export type SkillInstallHandler = (skill: { name: string; description: string; code: string; permissions: string[] }) => Promise<{ success: boolean; message: string }>;
export type MCPConnectHandler = (server: { name: string; url: string }) => Promise<{ success: boolean; message: string }>;
export type ConfigUpdateHandler = (config: { model?: string; temperature?: number; maxTokens?: number; baseUrl?: string }) => Promise<{ success: boolean; message: string }>;
export type SettingsUpdateHandler = (section: string, data: Record<string, unknown>) => Promise<{ success: boolean; message: string }>;

export class DashboardServer {
  private httpServer: ReturnType<typeof createServer> | null = null;
  private wss: WebSocketServer | null = null;
  private clients: Set<WebSocket> = new Set();
  private state: DashboardState;
  private chatHandler: ChatHandler | null = null;
  private skillInstallHandler: SkillInstallHandler | null = null;
  private mcpConnectHandler: MCPConnectHandler | null = null;
  private configUpdateHandler: ConfigUpdateHandler | null = null;
  private settingsUpdateHandler: SettingsUpdateHandler | null = null;
  private _pingInterval: ReturnType<typeof setInterval> | null = null;

  constructor(private port: number = 3333) {
    this.state = this.getDefaultState();
  }

  onChat(handler: ChatHandler): void { this.chatHandler = handler; }
  onSkillInstall(handler: SkillInstallHandler): void { this.skillInstallHandler = handler; }
  onMCPConnect(handler: MCPConnectHandler): void { this.mcpConnectHandler = handler; }
  onConfigUpdate(handler: ConfigUpdateHandler): void { this.configUpdateHandler = handler; }
  onSettingsUpdate(handler: SettingsUpdateHandler): void { this.settingsUpdateHandler = handler; }

  updateState(partial: Partial<DashboardState>): void {
    Object.assign(this.state, partial);
    this.broadcast({ type: 'state-update', data: this.state });
  }

  addDecisionTrace(entry: DashboardState['decisionTrace'][0]): void {
    this.state.decisionTrace.unshift(entry);
    if (this.state.decisionTrace.length > 200) this.state.decisionTrace = this.state.decisionTrace.slice(0, 200);
    // Also push as alert if block/warn
    if (entry.type !== 'allow') {
      this.state.alerts.unshift({
        id: `alert-${Date.now()}`, timestamp: entry.timestamp,
        severity: entry.type === 'block' ? 'critical' : 'warn',
        source: entry.emitter, message: `${entry.action} — ${entry.detail}`, acknowledged: false,
      });
      this.state.alertsActive = this.state.alerts.filter(a => !a.acknowledged).length;
      this.state.alertsCritical = this.state.alerts.filter(a => !a.acknowledged && a.severity === 'critical').length;
      this.state.alertsWarning = this.state.alerts.filter(a => !a.acknowledged && a.severity === 'warn').length;
    }
    this.broadcast({ type: 'state-update', data: this.state });
  }

  addActivity(entry: DashboardState['activities'][0]): void {
    this.state.activities.unshift(entry);
    if (this.state.activities.length > 200) this.state.activities = this.state.activities.slice(0, 200);
    this.broadcast({ type: 'activity', data: entry });
  }

  async start(): Promise<void> {
    this.httpServer = createServer(async (req, res) => { await this.handleRequest(req, res); });
    this.wss = new WebSocketServer({ server: this.httpServer });
    this.wss.on('connection', (ws) => {
      this.clients.add(ws);
      (ws as any).__alive = true;
      ws.send(JSON.stringify({ type: 'state-update', data: this.state }));
      ws.on('close', () => this.clients.delete(ws));
      ws.on('error', () => this.clients.delete(ws));
      ws.on('pong', () => { (ws as any).__alive = true; });
    });
    // Ping interval: detect dead clients every 30s
    this._pingInterval = setInterval(() => {
      for (const ws of this.clients) {
        if ((ws as any).__alive === false) { ws.terminate(); this.clients.delete(ws); continue; }
        (ws as any).__alive = false;
        ws.ping();
      }
    }, 30000);
    return new Promise((resolve) => { this.httpServer!.listen(this.port, () => resolve()); });
  }

  async stop(): Promise<void> { if (this._pingInterval) clearInterval(this._pingInterval); this.wss?.close(); this.httpServer?.close(); }

  private broadcast(message: unknown): void {
    const data = JSON.stringify(message);
    for (const client of this.clients) { if (client.readyState === WebSocket.OPEN) client.send(data); }
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = req.url ?? '/';
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };

    if (req.method === 'OPTIONS') { res.writeHead(204, cors); res.end(); return; }

    if (url === '/api/state') {
      res.writeHead(200, { 'Content-Type': 'application/json', ...cors });
      res.end(JSON.stringify(this.state)); return;
    }

    if (url === '/api/chat' && req.method === 'POST') {
      const MAX_BODY_SIZE = 65536; // 64KB
      let body = '';
      let overflow = false;
      for await (const chunk of req) {
        body += chunk;
        if (body.length > MAX_BODY_SIZE) { overflow = true; break; }
      }
      if (overflow) {
        res.writeHead(413, { 'Content-Type': 'application/json', ...cors });
        res.end(JSON.stringify({ error: 'Request body too large (max 64KB)' })); return;
      }
      try {
        const { message } = JSON.parse(body);
        if (!message || !this.chatHandler) {
          res.writeHead(400, { 'Content-Type': 'application/json', ...cors });
          res.end(JSON.stringify({ error: 'No message or chat handler not ready' })); return;
        }
        const reply = await this.chatHandler(message);
        res.writeHead(200, { 'Content-Type': 'application/json', ...cors });
        res.end(JSON.stringify({ reply }));
      } catch (err: any) {
        res.writeHead(500, { 'Content-Type': 'application/json', ...cors });
        res.end(JSON.stringify({ error: err.message ?? 'Internal error' }));
      }
      return;
    }

    // ─── Skill Install API ───
    if (url === '/api/skill/install' && req.method === 'POST') {
      let body = ''; let bodySize = 0;
      for await (const chunk of req) { bodySize += chunk.length; if (bodySize > 65536) { res.writeHead(413, cors); res.end('Body too large'); return; } body += chunk; }
      try {
        const data = JSON.parse(body);
        if (!this.skillInstallHandler) { res.writeHead(503, { 'Content-Type': 'application/json', ...cors }); res.end(JSON.stringify({ success: false, message: 'Handler not ready' })); return; }
        const result = await this.skillInstallHandler(data);
        res.writeHead(200, { 'Content-Type': 'application/json', ...cors });
        res.end(JSON.stringify(result));
      } catch (err: any) { res.writeHead(500, { 'Content-Type': 'application/json', ...cors }); res.end(JSON.stringify({ success: false, message: err.message })); }
      return;
    }

    // ─── MCP Connect API ───
    if (url === '/api/mcp/connect' && req.method === 'POST') {
      let body = ''; let bodySize = 0;
      for await (const chunk of req) { bodySize += chunk.length; if (bodySize > 65536) { res.writeHead(413, cors); res.end('Body too large'); return; } body += chunk; }
      try {
        const data = JSON.parse(body);
        if (!this.mcpConnectHandler) { res.writeHead(503, { 'Content-Type': 'application/json', ...cors }); res.end(JSON.stringify({ success: false, message: 'Handler not ready' })); return; }
        const result = await this.mcpConnectHandler(data);
        res.writeHead(200, { 'Content-Type': 'application/json', ...cors });
        res.end(JSON.stringify(result));
      } catch (err: any) { res.writeHead(500, { 'Content-Type': 'application/json', ...cors }); res.end(JSON.stringify({ success: false, message: err.message })); }
      return;
    }

    // ─── Config Update API ───
    if (url === '/api/config/update' && req.method === 'POST') {
      let body = ''; let bodySize = 0;
      for await (const chunk of req) { bodySize += chunk.length; if (bodySize > 65536) { res.writeHead(413, cors); res.end('Body too large'); return; } body += chunk; }
      try {
        const data = JSON.parse(body);
        if (!this.configUpdateHandler) { res.writeHead(503, { 'Content-Type': 'application/json', ...cors }); res.end(JSON.stringify({ success: false, message: 'Handler not ready' })); return; }
        const result = await this.configUpdateHandler(data);
        res.writeHead(200, { 'Content-Type': 'application/json', ...cors });
        res.end(JSON.stringify(result));
      } catch (err: any) { res.writeHead(500, { 'Content-Type': 'application/json', ...cors }); res.end(JSON.stringify({ success: false, message: err.message })); }
      return;
    }

    // ─── Settings Update API (personality, gateway, security, memory, terminal, cron) ───
    if (url?.startsWith('/api/settings/') && req.method === 'POST') {
      const section = url.replace('/api/settings/', '');
      let body = ''; let bodySize = 0;
      for await (const chunk of req) { bodySize += chunk.length; if (bodySize > 65536) { res.writeHead(413, cors); res.end('Body too large'); return; } body += chunk; }
      try {
        const data = JSON.parse(body);
        if (!this.settingsUpdateHandler) { res.writeHead(503, { 'Content-Type': 'application/json', ...cors }); res.end(JSON.stringify({ success: false, message: 'Handler not ready' })); return; }
        const result = await this.settingsUpdateHandler(section, data);
        res.writeHead(200, { 'Content-Type': 'application/json', ...cors });
        res.end(JSON.stringify(result));
      } catch (err: any) { res.writeHead(500, { 'Content-Type': 'application/json', ...cors }); res.end(JSON.stringify({ success: false, message: err.message })); }
      return;
    }

    if (url === '/' || url === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(DASHBOARD_HTML); return;
    }
    res.writeHead(404); res.end('Not found');
  }

  private getDefaultState(): DashboardState {
    // ALL zeros/empty — real data is pushed by OdinAgent.syncDashboard()
    return {
      agentName: 'ODIN by AgentLayers', did: 'did:odin:ed25519:initializing...', trustMode: 'SAFE',
      gatewayStatus: 'offline', uptime: '0s', llmModel: 'initializing...', llmProvider: 'none', llmMaxTokens: 0, llmTemperature: 0,
      trustScore: 0, trustScoreDelta: 0,
      skillsInstalled: 0, skillsTier1Plus: 0, skillsTier0: 0,
      agentsConnected: 0, agentsCertified: 0, agentsMonitoring: 0,
      alertsActive: 0, alertsCritical: 0, alertsWarning: 0,
      activeSessions: 0, tokensToday: 0, channels: 0,
      dimensions: { performance: 0, transparency: 0, security: 0, compliance: 0, reputation: 0, reliability: 0 },
      trustHistory: [],
      nextEvaluation: 'pending', certifiedBy: 'none',
      aegisLayers: [],
      circuitBreakerState: 'CLOSED',
      circuitBreakerMetrics: { totalCalls: 0, failures: 0, semanticFailures: 0 },
      skills: [],
      peerAgents: [], mcpServers: [],
      decisionTrace: [], alerts: [], activities: [],
      compliance: { euAiAct: 0, owaspAsi: '0/10', singaporeMgf: 0, slsa: 0 },
      performance: { latencyMs: 0, taskCompletion: 0, tokenOverhead: 0, merkleVerifyMs: 0 },
      recentChats: [],
    };
  }
}

// ─── DASHBOARD HTML v2.0 — 3-column Claw Dash layout + AEGIS ───

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ODIN — Dashboard v2.0</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"><\/script>
<style>
:root {
  --bg: #0D1117; --bg-card: #161B22; --bg-hover: #1C2230; --border: #30363D;
  --text: #E6EDF3; --text-muted: #8B949E; --text-dim: #484F58;
  --green: #1D9E75; --green-bg: rgba(29,158,117,0.12);
  --orange: #D29922; --orange-bg: rgba(210,153,34,0.12);
  --red: #F85149; --red-bg: rgba(248,81,73,0.12);
  --blue: #58A6FF; --blue-bg: rgba(88,166,255,0.10);
  --purple: #BC8CFF; --purple-bg: rgba(188,140,255,0.10);
  --sidebar-w: 260px; --panel-w: 340px;
  --mono: 'JetBrains Mono','Fira Code','Cascadia Code',monospace;
  --sans: 'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--sans);background:var(--bg);color:var(--text);height:100vh;overflow:hidden}

/* ─── 3-Column Layout ─── */
.app{display:flex;height:100vh}

/* ─── Sidebar ─── */
.sidebar{width:var(--sidebar-w);background:var(--bg);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;overflow:hidden}
.sidebar-header{padding:16px 18px;border-bottom:1px solid var(--border)}
.sidebar-logo{font-size:16px;font-weight:700;letter-spacing:0.5px;display:flex;align-items:center;gap:8px}
.sidebar-logo span{color:var(--blue)}
.sidebar-did{font-family:var(--mono);font-size:9px;color:var(--text-dim);margin-top:6px;word-break:break-all;line-height:1.4}
.btn-new-chat{display:flex;align-items:center;justify-content:center;gap:6px;width:calc(100% - 36px);margin:12px 18px;padding:9px;border-radius:8px;border:1px solid var(--border);background:transparent;color:var(--text);font-size:13px;cursor:pointer;transition:all .2s}
.btn-new-chat:hover{background:var(--bg-hover);border-color:var(--blue)}
.sidebar-search{margin:0 18px 12px;position:relative}
.sidebar-search input{width:100%;padding:7px 10px 7px 30px;border-radius:6px;border:1px solid var(--border);background:var(--bg-card);color:var(--text);font-size:12px;outline:none}
.sidebar-search input:focus{border-color:var(--blue)}
.sidebar-search::before{content:'⌕';position:absolute;left:10px;top:7px;color:var(--text-dim);font-size:13px}

.sidebar-nav{flex:1;overflow-y:auto;padding:4px 0}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 18px;font-size:13px;color:var(--text-muted);cursor:pointer;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{background:var(--bg-hover);color:var(--text)}
.nav-item.active{color:var(--text);background:var(--bg-card);border-left-color:var(--blue)}
.nav-icon{width:16px;text-align:center;font-size:14px}
.nav-section-title{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);padding:16px 18px 6px;font-weight:600}

.sidebar-chats{border-top:1px solid var(--border);padding:8px 0;overflow-y:auto;max-height:200px}
.chat-item{padding:6px 18px;font-size:12px;color:var(--text-muted);cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;transition:background .15s}
.chat-item:hover{background:var(--bg-hover);color:var(--text)}
.chat-date{font-size:10px;color:var(--text-dim);padding:6px 18px 2px}

/* ─── Main Content ─── */
.main{flex:1;overflow-y:auto;padding:0}
.main-header{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--border);background:var(--bg-card);position:sticky;top:0;z-index:10}
.main-header-left{display:flex;align-items:center;gap:12px}
.main-title{font-size:16px;font-weight:600}
.status-dot{width:8px;height:8px;border-radius:50%;animation:pulse 2s infinite}
.status-connected{background:var(--green)}
.status-offline{background:var(--red)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.main-header-info{font-size:12px;color:var(--text-muted)}
.main-header-right{display:flex;align-items:center;gap:10px}
.header-badge{font-size:11px;font-weight:600;padding:4px 12px;border-radius:14px;display:inline-flex;align-items:center;gap:5px}
.header-badge::before{content:'';width:6px;height:6px;border-radius:50%}
.badge-safe{background:var(--green-bg);color:var(--green)}.badge-safe::before{background:var(--green)}
.badge-caution{background:var(--orange-bg);color:var(--orange)}.badge-caution::before{background:var(--orange)}
.badge-degraded{background:var(--red-bg);color:var(--red)}.badge-degraded::before{background:var(--red)}
.header-time{font-family:var(--mono);font-size:11px;color:var(--text-dim)}

.main-body{padding:20px 24px}

/* ─── KPI Row ─── */
.kpi-row{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap}
.kpi{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:14px 18px;flex:1;min-width:140px}
.kpi-label{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);margin-bottom:4px}
.kpi-val{font-family:var(--mono);font-size:24px;font-weight:700}
.kpi-sub{font-size:11px;color:var(--text-dim);margin-top:2px}
.kpi-up{color:var(--green)} .kpi-down{color:var(--red)}

/* ─── Health Cards ─── */
.health-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-bottom:20px}
.health-card{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:16px;transition:border-color .2s;cursor:pointer;position:relative}
.health-card:hover{border-color:var(--blue)}
.health-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.health-name{font-size:13px;font-weight:600}
.live-badge{font-size:9px;font-weight:700;letter-spacing:.5px;padding:2px 8px;border-radius:10px;text-transform:uppercase}
.live-green{background:var(--green-bg);color:var(--green);animation:pulse 2s infinite}
.live-orange{background:var(--orange-bg);color:var(--orange)}
.live-red{background:var(--red-bg);color:var(--red)}
.health-rows{display:flex;flex-direction:column;gap:4px}
.health-row{display:flex;justify-content:space-between;font-size:11px}
.health-row-label{color:var(--text-muted)}
.health-row-val{font-family:var(--mono);color:var(--text)}
.health-open{font-size:11px;color:var(--blue);margin-top:8px;display:inline-block}

/* ─── Topology placeholder ─── */
.topology{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:20px;min-height:200px;position:relative}
.topology-title{font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px}
.topology-graph{display:flex;align-items:center;justify-content:center;gap:40px;padding:24px 0}
.topo-node{display:flex;flex-direction:column;align-items:center;gap:6px}
.topo-circle{width:52px;height:52px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;border:2px solid var(--border);transition:all .3s}
.topo-circle-green{border-color:var(--green);background:var(--green-bg)}
.topo-circle-blue{border-color:var(--blue);background:var(--blue-bg)}
.topo-circle-purple{border-color:var(--purple);background:var(--purple-bg)}
.topo-label{font-size:11px;font-weight:600}
.topo-sub{font-size:9px;color:var(--text-muted);font-family:var(--mono)}
.topo-edge{width:60px;height:2px;background:var(--border);position:relative}
.topo-edge-label{position:absolute;top:-14px;left:50%;transform:translateX(-50%);font-size:9px;color:var(--text-dim);font-family:var(--mono);white-space:nowrap}
.topo-bar{display:flex;gap:8px;padding:10px;background:var(--bg);border-radius:6px;margin-top:10px;flex-wrap:wrap}
.topo-job{font-size:10px;font-family:var(--mono);padding:3px 8px;border-radius:4px;background:var(--bg-card);border:1px solid var(--border);color:var(--text-muted)}

/* ─── Section panels ─── */
.section{display:none}.section.active{display:block}
.panel{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:18px;margin-bottom:16px}
.panel-title{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);margin-bottom:14px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}

/* ─── Trust Score (Security) ─── */
.donut-wrapper{display:flex;align-items:center;gap:24px;margin-bottom:16px}
.donut-container{position:relative;width:130px;height:130px;flex-shrink:0}
.donut-center{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}
.donut-score{font-family:var(--mono);font-size:28px;font-weight:700}
.donut-label{font-size:10px;color:var(--text-muted)}
.dim-row{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.dim-name{width:130px;font-size:11px;color:var(--text-muted);flex-shrink:0}
.dim-bar{flex:1;height:6px;background:var(--bg);border-radius:3px;overflow:hidden}
.dim-fill{height:100%;border-radius:3px;transition:width .6s}
.dim-val{font-family:var(--mono);font-size:11px;width:30px;text-align:right;flex-shrink:0}
.fill-g{background:var(--green)}.fill-o{background:var(--orange)}.fill-r{background:var(--red)}
.chart-box{height:140px;margin-top:12px}

/* ─── AEGIS Layers ─── */
.aegis{display:flex;flex-direction:column;gap:8px;padding:12px;margin-bottom:6px;background:var(--bg);border-radius:6px;border:1px solid var(--border)}
.aegis-header{display:flex;align-items:center;gap:8px}
.aegis-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dot-actif{background:var(--green)}.dot-alerte{background:var(--orange);animation:pulse 1.5s infinite}.dot-inactif{background:var(--text-dim)}
.aegis-info{flex:1;min-width:0}.aegis-name{font-size:13px;font-weight:600;white-space:nowrap}.aegis-desc{font-size:10px;color:var(--text-muted)}
.st-badge{font-size:9px;font-weight:600;padding:2px 8px;border-radius:3px;flex-shrink:0;text-transform:uppercase;letter-spacing:.3px}
.st-actif{background:var(--green-bg);color:var(--green)}.st-alerte{background:var(--orange-bg);color:var(--orange)}
.aegis-footer{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.aegis-metric{font-family:var(--mono);font-size:10px;color:var(--text-muted);flex:1;min-width:0}
.aegis-tags{display:flex;gap:3px;flex-wrap:wrap;flex-shrink:0}
.aegis-tag{font-size:8px;padding:1px 5px;border-radius:3px;background:var(--blue-bg);color:var(--blue);font-family:var(--mono)}

/* Circuit Breakers */
.cb-row{display:flex;gap:6px;align-items:center;margin-top:12px;flex-wrap:wrap}
.cb{font-size:10px;font-family:var(--mono);padding:5px 10px;border-radius:5px;border:1px solid var(--border);color:var(--text-dim);background:var(--bg)}
.cb-active{border-color:var(--green);color:var(--green);background:var(--green-bg);font-weight:600}
.cb-active.cb-deg{border-color:var(--orange);color:var(--orange);background:var(--orange-bg)}
.cb-active.cb-open{border-color:var(--red);color:var(--red);background:var(--red-bg)}
.cb-active.cb-half{border-color:var(--blue);color:var(--blue);background:var(--blue-bg)}
.cb-arrow{color:var(--text-dim);font-size:9px}

/* ─── Tables ─── */
.tbl{width:100%;border-collapse:collapse}
.tbl th{font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)}
.tbl td{font-size:12px;padding:7px 8px;border-bottom:1px solid var(--border)}
.tbl tr:hover{background:var(--bg-hover)}
.tier{font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px;display:inline-block}
.t0{background:rgba(72,79,88,.2);color:var(--text-dim)}.t1{background:var(--green-bg);color:var(--green)}.t2{background:var(--blue-bg);color:var(--blue)}
.trust-bar{width:50px;height:5px;background:var(--bg);border-radius:3px;overflow:hidden;display:inline-block;vertical-align:middle;margin-right:5px}
.trust-fill{height:100%;border-radius:3px}
.mcp-st{font-size:9px;font-weight:600;padding:2px 7px;border-radius:3px}

/* ─── Compliance ─── */
.comp-row{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.comp-name{width:160px;font-size:11px;flex-shrink:0}
.comp-bar{flex:1;height:6px;background:var(--bg);border-radius:3px;overflow:hidden}
.comp-fill{height:100%;border-radius:3px}
.comp-val{font-family:var(--mono);font-size:11px;width:40px;text-align:right;flex-shrink:0}
.perf-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px}
.perf{background:var(--bg);border-radius:6px;padding:10px;border:1px solid var(--border)}
.perf-label{font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px}
.perf-val{font-family:var(--mono);font-size:18px;font-weight:700;margin:3px 0}
.perf-target{font-size:9px;color:var(--text-dim)}

/* ─── Decision Trace ─── */
.trace-list{max-height:300px;overflow-y:auto}
.trace{display:flex;gap:8px;padding:6px 8px;border-bottom:1px solid var(--border);font-size:11px;cursor:pointer;transition:background .15s}
.trace:hover{background:var(--bg-hover)}
.trace-time{font-family:var(--mono);color:var(--text-dim);width:60px;flex-shrink:0}
.trace-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0;margin-top:4px}
.td-allow{background:var(--green)}.td-warn{background:var(--orange)}.td-block{background:var(--red)}
.trace-em{font-weight:600}.trace-det{color:var(--text-muted)}
.trace-layer{font-size:9px;color:var(--text-dim);font-family:var(--mono)}

/* ─── Activity list ─── */
.act{display:flex;gap:8px;padding:8px;border-bottom:1px solid var(--border);font-size:12px}
.act-time{font-family:var(--mono);font-size:10px;color:var(--text-dim);width:60px;flex-shrink:0}
.act-type{font-size:9px;padding:2px 6px;border-radius:3px;font-weight:600;flex-shrink:0}
.act-tool{background:var(--blue-bg);color:var(--blue)}.act-chat{background:var(--green-bg);color:var(--green)}
.act-a2a{background:var(--purple-bg);color:var(--purple)}.act-sec{background:var(--orange-bg);color:var(--orange)}
.act-info{flex:1}.act-action{font-weight:500}.act-detail{color:var(--text-muted);font-size:11px}

/* ─── Right Panel (Alerts) ─── */
.right-panel{width:var(--panel-w);background:var(--bg);border-left:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;overflow:hidden}
.right-header{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--border)}
.right-title{font-size:13px;font-weight:600}
.btn-clear{font-size:10px;padding:4px 10px;border-radius:5px;border:1px solid var(--border);background:transparent;color:var(--text-muted);cursor:pointer;transition:all .2s}
.btn-clear:hover{background:var(--bg-hover);color:var(--text)}
.right-list{flex:1;overflow-y:auto;padding:8px 0}
.alert-item{padding:10px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.alert-item:hover{background:var(--bg-hover)}
.alert-item.ack{opacity:.4}
.alert-top{display:flex;align-items:center;gap:6px;margin-bottom:4px}
.alert-sev{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.sev-critical{background:var(--red)}.sev-warn{background:var(--orange)}.sev-info{background:var(--blue)}
.alert-source{font-size:11px;font-weight:600}.alert-time{font-size:10px;color:var(--text-dim);margin-left:auto;font-family:var(--mono)}
.alert-msg{font-size:11px;color:var(--text-muted);line-height:1.4}
.right-empty{padding:40px 16px;text-align:center;color:var(--text-dim);font-size:12px;line-height:1.6}

/* Scrollbar */
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}::-webkit-scrollbar-thumb:hover{background:var(--text-dim)}

.empty{font-size:12px;color:var(--text-dim);text-align:center;padding:24px}

/* ─── Chat UI ─── */
.chat-section{display:flex;flex-direction:column;height:calc(100vh - 60px)}
.chat-messages{flex:1;overflow-y:auto;padding:16px 0;display:flex;flex-direction:column;gap:12px}
.chat-msg{display:flex;gap:10px;padding:0 4px;max-width:85%;animation:fadeIn .3s ease}
.chat-msg-user{align-self:flex-end;flex-direction:row-reverse}
.chat-msg-agent{align-self:flex-start}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.chat-avatar{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0;border:1px solid var(--border)}
.chat-avatar-user{background:var(--blue-bg);color:var(--blue)}
.chat-avatar-agent{background:var(--green-bg);color:var(--green)}
.chat-bubble{padding:10px 14px;border-radius:12px;font-size:13px;line-height:1.5;white-space:pre-wrap;word-break:break-word}
.chat-bubble-user{background:var(--blue-bg);border:1px solid rgba(88,166,255,.2);border-bottom-right-radius:4px}
.chat-bubble-agent{background:var(--bg-card);border:1px solid var(--border);border-bottom-left-radius:4px}
.chat-bubble-agent .chat-meta{font-size:10px;color:var(--text-dim);margin-top:6px;font-family:var(--mono);display:flex;gap:10px}
.chat-typing{align-self:flex-start;display:flex;gap:10px;padding:0 4px}
.chat-typing .chat-bubble{color:var(--text-muted)}
.typing-dots{display:inline-flex;gap:3px}.typing-dots span{width:5px;height:5px;border-radius:50%;background:var(--text-muted);animation:blink 1.4s infinite both}
.typing-dots span:nth-child(2){animation-delay:.2s}.typing-dots span:nth-child(3){animation-delay:.4s}
@keyframes blink{0%,80%,100%{opacity:.2}40%{opacity:1}}
.chat-input-row{display:flex;gap:8px;padding:12px 0 4px;border-top:1px solid var(--border)}
.chat-input{flex:1;padding:10px 14px;border-radius:10px;border:1px solid var(--border);background:var(--bg-card);color:var(--text);font-size:13px;font-family:var(--sans);outline:none;resize:none;min-height:42px;max-height:120px}
.chat-input:focus{border-color:var(--blue)}
.chat-input::placeholder{color:var(--text-dim)}
.chat-send{padding:10px 18px;border-radius:10px;border:none;background:var(--blue);color:#fff;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .2s;flex-shrink:0}
.chat-send:hover{opacity:.85}
.chat-send:disabled{opacity:.3;cursor:not-allowed}
.chat-empty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;color:var(--text-dim)}
.chat-empty-icon{font-size:48px;opacity:.3}
.chat-empty-title{font-size:16px;font-weight:600;color:var(--text-muted)}
.chat-empty-sub{font-size:12px;text-align:center;line-height:1.5}

/* ─── Tooltips ─── */
.tip{position:relative;cursor:help}
.tip::after{content:attr(data-tip);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:#1c2128;color:#c9d1d9;font-size:11px;line-height:1.4;padding:6px 10px;border-radius:6px;border:1px solid var(--border);white-space:normal;width:max-content;max-width:260px;opacity:0;pointer-events:none;transition:opacity .2s;z-index:999;font-weight:400;font-family:var(--sans);text-transform:none;letter-spacing:0}
.tip:hover::after{opacity:1}

/* ─── Forms ─── */
.form-row{display:flex;align-items:flex-start;gap:8px;margin-bottom:8px}
.form-label{font-size:11px;color:var(--text-muted);width:100px;flex-shrink:0;padding-top:7px}
.form-input,.form-textarea{flex:1;padding:7px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--text);font-size:12px;font-family:var(--mono);outline:none}
.form-input:focus,.form-textarea:focus{border-color:var(--blue)}
.form-textarea{resize:vertical;font-family:var(--mono);min-height:50px}
.form-input::placeholder,.form-textarea::placeholder{color:var(--text-dim)}
select.form-input{cursor:pointer;appearance:auto}
.btn-action{font-size:11px;padding:7px 16px;border-radius:6px;border:1px solid var(--blue);background:transparent;color:var(--blue);cursor:pointer;transition:all .2s;margin-top:6px}
.btn-action:hover{background:var(--blue-bg)}
.btn-action:disabled{opacity:.4;cursor:not-allowed}
.form-status{font-size:11px;margin-left:10px;vertical-align:middle}
.form-ok{color:var(--green)}.form-err{color:var(--red)}
</style>
</head>
<body>
<div class="app">

<!-- ─── SIDEBAR ─── -->
<aside class="sidebar">
  <div class="sidebar-header">
    <div class="sidebar-logo">⚡ <span>ODIN</span></div>
    <div class="sidebar-did" id="sb-did">did:odin:ed25519:loading...</div>
  </div>
  <button class="btn-new-chat" id="btn-new-chat">+ New Chat</button>
  <div class="sidebar-search"><input type="text" placeholder="Search..."></div>
  <nav class="sidebar-nav">
    <div class="nav-section-title">Navigation</div>
    <div class="nav-item active" data-section="home" title="KPIs, health cards, and agent topology overview"><span class="nav-icon">⌂</span> Home</div>
    <div class="nav-item" data-section="activity" title="Live feed of tool calls, chats, A2A events, and security decisions"><span class="nav-icon">◷</span> Activity</div>
    <div class="nav-item" data-section="system" title="Configure LLM, skills, MCP servers, gateway, security policies, and terminal"><span class="nav-icon">⚙</span> System</div>
    <div class="nav-item" data-section="security" title="Trust score dimensions, AEGIS layers, circuit breaker, decision trace, and compliance"><span class="nav-icon">⛨</span> Security</div>
  </nav>
  <div class="sidebar-chats">
    <div class="nav-section-title">Recent Chats</div>
    <div id="recent-chats"><div class="chat-item" style="color:var(--text-dim)">No conversations yet</div></div>
  </div>
</aside>

<!-- ─── MAIN CONTENT ─── -->
<div class="main">
  <div class="main-header">
    <div class="main-header-left">
      <div class="status-dot status-connected" id="gw-dot"></div>
      <div>
        <div class="main-title" id="section-title">Operations Overview</div>
        <div class="main-header-info" id="gw-info">Gateway connected · DID actif</div>
      </div>
    </div>
    <div class="main-header-right">
      <div class="header-badge badge-safe" id="hd-badge">SAFE</div>
      <div class="header-time" id="utc-clock"></div>
    </div>
  </div>
  <div class="main-body">

    <!-- SECTION: HOME -->
    <div class="section active" id="sec-home">
      <div class="kpi-row" id="kpi-row"></div>
      <div class="health-grid" id="health-grid"></div>
      <div class="topology">
        <div class="topology-title">Agent Topology</div>
        <div class="topology-graph" id="topo-graph"></div>
        <div class="topo-bar" id="topo-bar"></div>
      </div>
    </div>

    <!-- SECTION: ACTIVITY -->
    <div class="section" id="sec-activity">
      <div class="panel">
        <div class="panel-title">Activity Feed — Tool Calls · Sessions · Events</div>
        <div id="activity-list" style="max-height:500px;overflow-y:auto"></div>
      </div>
    </div>

    <!-- SECTION: SYSTEM -->
    <div class="section" id="sec-system">
      <!-- LLM Config (editable) -->
      <div class="two-col">
        <div class="panel">
          <div class="panel-title tip" data-tip="CaMeL Dual-LLM architecture: a Privileged model plans tool calls, a Quarantined model processes untrusted data. This prevents prompt injection by design.">LLM Router — Configuration</div>
          <div class="health-rows" id="sys-llm"></div>
          <div style="border-top:1px solid var(--border);margin-top:12px;padding-top:12px">
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;font-weight:600">Edit Configuration</div>
            <div class="form-row"><label class="form-label tip" data-tip="LLM backend: Ollama (local, private), Anthropic (Claude API), OpenAI, or None to run without LLM">Provider</label><select class="form-input" id="cfg-provider"><option value="">— keep current —</option><option value="ollama">Ollama (local)</option><option value="anthropic">Anthropic</option><option value="openai">OpenAI</option><option value="none">None</option></select></div>
            <div class="form-row"><label class="form-label tip" data-tip="Model name used by both Privileged and Quarantined LLMs. Ex: gemma3, claude-sonnet-4-20250514, gpt-4o">Model</label><input class="form-input" id="cfg-model" placeholder="gemma3"></div>
            <div class="form-row"><label class="form-label tip" data-tip="Required for Anthropic or OpenAI. Not needed for Ollama (local). Stored in memory only, never persisted.">API Key</label><input class="form-input" id="cfg-apikey" type="password" placeholder="sk-... (for Anthropic/OpenAI)"></div>
            <div class="form-row"><label class="form-label tip" data-tip="Controls randomness: 0 = deterministic, 1 = creative, 2 = very random. Default 0.7 is a balanced setting.">Temperature</label><input class="form-input" id="cfg-temp" type="number" step="0.1" min="0" max="2" placeholder="0.7"></div>
            <div class="form-row"><label class="form-label tip" data-tip="Maximum tokens the LLM can generate per response. Higher = longer responses but slower and more costly.">Max Tokens</label><input class="form-input" id="cfg-tokens" type="number" placeholder="4096"></div>
            <div class="form-row"><label class="form-label tip" data-tip="API endpoint URL. For Ollama: http://localhost:11434. For OpenAI-compatible APIs, set the base URL here.">Base URL</label><input class="form-input" id="cfg-url" placeholder="http://localhost:11434"></div>
            <button class="btn-action" onclick="updateConfig()">Apply Changes</button>
            <span class="form-status" id="cfg-status"></span>
          </div>
        </div>
        <div class="panel">
          <div class="panel-title tip" data-tip="Active messaging channels. CLI is always available. Configure Telegram, Discord, or Slack in Gateway settings.">Channels</div>
          <div id="sys-channels"><div class="empty">CLI active · Telegram/Discord available</div></div>
        </div>
      </div>

      <!-- Skills (table + install form) -->
      <div class="two-col">
        <div class="panel">
          <div class="panel-title tip" data-tip="Tools available to the agent. Each skill has a Trust Tier (T0-T2) and runs in a Sandbox Ring (0-2) with isolation constraints.">Skills installés — Trust Tiers</div>
          <table class="tbl"><thead><tr><th class="tip" data-tip="Tool name as registered in the agent">Skill</th><th class="tip" data-tip="Trust tier: T0=untrusted, T1=verified, T2=built-in trusted">Tier</th><th class="tip" data-tip="Sandbox ring: 0=read-only (5s), 1=read/write (30s), 2=full access (60s, needs approval)">Ring</th><th class="tip" data-tip="AgentLayers safety score (null = not scanned)">Score</th></tr></thead><tbody id="sys-skills"></tbody></table>
        </div>
        <div class="panel">
          <div class="panel-title tip" data-tip="Add a custom tool. It will be scanned by the security pipeline and assigned a trust tier based on its permissions.">Installer un Skill</div>
          <div class="form-row"><label class="form-label tip" data-tip="Unique identifier for this tool. Used in LLM tool calls.">Nom</label><input class="form-input" id="skill-name" placeholder="ex: weather_lookup"></div>
          <div class="form-row"><label class="form-label tip" data-tip="Human-readable description shown to the LLM so it knows when to use this tool.">Description</label><input class="form-input" id="skill-desc" placeholder="ex: Get weather for a city"></div>
          <div class="form-row"><label class="form-label tip" data-tip="JSON Schema defining the tool parameters. The LLM generates arguments matching this schema.">Paramètres (JSON)</label><textarea class="form-textarea" id="skill-params" rows="3" placeholder='{"city":{"type":"string","description":"City name"}}'></textarea></div>
          <div class="form-row"><label class="form-label tip" data-tip="JavaScript code executed when the tool is called. Has access to the arguments object. Must return a string.">Code du handler</label><textarea class="form-textarea" id="skill-code" rows="5" placeholder="const res = await fetch(...);\nreturn res.text();"></textarea></div>
          <div class="form-row"><label class="form-label tip" data-tip="Capabilities this tool requires. Affects which sandbox ring it can run in.">Permissions</label><input class="form-input" id="skill-perms" placeholder="network.read, file.read (comma-separated)"></div>
          <div class="form-row"><label class="form-label tip" data-tip="Ring 0: read-only, no network, 5s timeout. Ring 1: read/write, controlled network, 30s. Ring 2: full access, requires human approval, 60s.">Ring</label>
            <select class="form-input" id="skill-ring"><option value="0">Ring 0 — Lecture seule</option><option value="1" selected>Ring 1 — Lecture/écriture</option><option value="2">Ring 2 — Accès complet (approval)</option></select>
          </div>
          <button class="btn-action" onclick="installSkill()">Installer le Skill</button>
          <span class="form-status" id="skill-status"></span>
        </div>
      </div>

      <!-- MCP Servers (table + connect form) -->
      <div class="two-col">
        <div class="panel">
          <div class="panel-title tip" data-tip="Model Context Protocol servers extend the agent with external tools and data sources. Each server is scanned and assigned a safety score.">MCP Servers connectés</div>
          <div id="sys-mcp"></div>
        </div>
        <div class="panel">
          <div class="panel-title tip" data-tip="Connect to an MCP server to add its tools to the agent. The server will be scanned by AgentLayers for safety.">Connecter un serveur MCP</div>
          <div class="form-row"><label class="form-label tip" data-tip="Display name for this MCP server in the dashboard.">Nom</label><input class="form-input" id="mcp-name" placeholder="ex: github-mcp"></div>
          <div class="form-row"><label class="form-label tip" data-tip="SSE or WebSocket endpoint URL of the MCP server.">URL</label><input class="form-input" id="mcp-url" placeholder="https://mcp.example.com/sse"></div>
          <button class="btn-action" onclick="connectMCP()">Connecter</button>
          <span class="form-status" id="mcp-status"></span>
        </div>
      </div>

      <!-- Agent Personality -->
      <div class="two-col">
        <div class="panel">
          <div class="panel-title tip" data-tip="Custom system prompt injected into every LLM call. Defines the agent's tone, behavior, and constraints.">Agent Personality — SOUL.md</div>
          <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px">Define who Odin is. This text is injected into every system prompt.</div>
          <textarea class="form-textarea" id="cfg-personality" rows="6" placeholder="You are a helpful, security-focused AI agent. You speak concisely and always verify before acting."></textarea>
          <div style="display:flex;gap:8px;margin-top:8px">
            <button class="btn-action" onclick="saveSetting('personality',{text:document.getElementById('cfg-personality').value})">Save Personality</button>
            <span class="form-status" id="personality-status"></span>
          </div>
        </div>
        <div class="panel">
          <div class="panel-title tip" data-tip="Merkle-verified memory store backed by SQLite. Every entry is signed with Ed25519 for tamper detection.">Memory — Configuration</div>
          <div class="form-row"><label class="form-label tip" data-tip="Maximum number of memory entries before oldest are pruned. Higher = more context but larger DB.">Max Entries</label><input class="form-input" id="mem-max" type="number" placeholder="10000"></div>
          <div class="form-row"><label class="form-label tip" data-tip="Path to the SQLite database file. Relative to the project root.">DB Path</label><input class="form-input" id="mem-path" placeholder="./odin-memory.db"></div>
          <button class="btn-action" onclick="saveSetting('memory',{maxEntries:parseInt(document.getElementById('mem-max').value)||undefined,dbPath:document.getElementById('mem-path').value||undefined})">Save Memory Config</button>
          <span class="form-status" id="memory-status"></span>
        </div>
      </div>

      <!-- Gateway + Security -->
      <div class="two-col">
        <div class="panel">
          <div class="panel-title tip" data-tip="Connect the agent to messaging platforms. Each gateway routes messages through the full security pipeline.">Gateway — Messaging Channels</div>
          <div class="form-row"><label class="form-label tip" data-tip="Primary input channel. CLI = terminal, Telegram/Discord/Slack = bot integration.">Type</label>
            <select class="form-input" id="gw-type"><option value="cli">CLI</option><option value="telegram">Telegram</option><option value="discord">Discord</option><option value="slack">Slack</option><option value="whatsapp">WhatsApp</option></select>
          </div>
          <div class="form-row"><label class="form-label tip" data-tip="Bot token from Telegram @BotFather. Required for Telegram gateway.">Telegram Token</label><input class="form-input" id="gw-telegram" type="password" placeholder="Bot token from @BotFather"></div>
          <div class="form-row"><label class="form-label tip" data-tip="Bot token from the Discord Developer Portal. Required for Discord gateway.">Discord Token</label><input class="form-input" id="gw-discord" type="password" placeholder="Discord bot token"></div>
          <div class="form-row"><label class="form-label tip" data-tip="Bot OAuth token from Slack App settings. Required for Slack gateway.">Slack Token</label><input class="form-input" id="gw-slack" type="password" placeholder="Slack bot token"></div>
          <div class="form-row"><label class="form-label tip" data-tip="Whitelist of user IDs allowed to interact. Empty = everyone can use the bot.">Allowed Users</label><input class="form-input" id="gw-users" placeholder="user1, user2 (comma-separated, empty=all)"></div>
          <div class="form-row"><label class="form-label tip" data-tip="If enabled, the bot only responds when @mentioned in group chats. DMs always work.">Require @mention</label><select class="form-input" id="gw-mention"><option value="false">No</option><option value="true">Yes (groups only)</option></select></div>
          <button class="btn-action" onclick="saveGateway()">Save Gateway Config</button>
          <span class="form-status" id="gateway-status"></span>
        </div>
        <div class="panel">
          <div class="panel-title tip" data-tip="Cedar-inspired policy engine. Evaluates every tool call against trust score, rate limits, ring constraints, and approval rules.">Security — Policies</div>
          <div class="form-row"><label class="form-label tip" data-tip="Manual: user confirms every sensitive action. Smart: LLM evaluates risk. Off: auto-approve (not recommended).">Approval Mode</label>
            <select class="form-input" id="sec-approval"><option value="manual">Manual — always ask</option><option value="smart">Smart — LLM decides</option><option value="off">Off — auto-approve all</option></select>
          </div>
          <div class="form-row"><label class="form-label tip" data-tip="Automatically redact API keys, passwords, and secrets from tool outputs and logs.">Redact Secrets</label><select class="form-input" id="sec-redact"><option value="true" selected>Yes</option><option value="false">No</option></select></div>
          <div class="form-row"><label class="form-label tip" data-tip="Rate limit: maximum tool calls per 24h. Exceeding this triggers a Cedar policy BLOCK.">Max Daily Calls</label><input class="form-input" id="sec-maxcalls" type="number" placeholder="1000"></div>
          <div class="form-row"><label class="form-label tip" data-tip="Session time-to-live. After this duration, the session is reset and conversation history is cleared.">Session TTL (sec)</label><input class="form-input" id="sec-ttl" type="number" placeholder="3600"></div>
          <div class="form-row"><label class="form-label tip" data-tip="Domains the agent is forbidden from accessing via network tools. Requests to these domains are blocked by IFC.">Blocked Domains</label><input class="form-input" id="sec-blocklist" placeholder="evil.com, malware.net (comma-separated)"></div>
          <div class="form-row"><label class="form-label tip" data-tip="Tools that always require explicit human approval before execution, regardless of trust score.">Require Approval</label><input class="form-input" id="sec-tools" placeholder="shell_exec, code_exec (comma-separated)"></div>
          <button class="btn-action" onclick="saveSecurity()">Save Security Config</button>
          <span class="form-status" id="security-status"></span>
        </div>
      </div>

      <!-- Terminal + Cron -->
      <div class="two-col">
        <div class="panel">
          <div class="panel-title tip" data-tip="Where shell_exec and code_exec tools run. Local = host machine. Docker = isolated container. SSH = remote server.">Terminal — Execution Backend</div>
          <div class="form-row"><label class="form-label tip" data-tip="Local: runs on host (fast, no isolation). Docker: sandboxed container (safe). SSH: remote execution.">Backend</label>
            <select class="form-input" id="term-backend"><option value="local">Local</option><option value="docker">Docker</option><option value="ssh">SSH</option></select>
          </div>
          <div class="form-row"><label class="form-label tip" data-tip="Maximum execution time for a single command. Killed after timeout to prevent runaway processes.">Timeout (sec)</label><input class="form-input" id="term-timeout" type="number" placeholder="180"></div>
          <div class="form-row"><label class="form-label tip" data-tip="Docker image used for sandboxed execution. Must have the tools the agent needs (Node, Python, etc.).">Docker Image</label><input class="form-input" id="term-docker" placeholder="nikolaik/python-nodejs:python3.11-nodejs20"></div>
          <div class="form-row"><label class="form-label tip" data-tip="SSH connection string for remote execution. Format: user@hostname">SSH Host</label><input class="form-input" id="term-ssh-host" placeholder="user@host"></div>
          <div class="form-row"><label class="form-label tip" data-tip="SSH port number. Default is 22.">SSH Port</label><input class="form-input" id="term-ssh-port" type="number" placeholder="22"></div>
          <button class="btn-action" onclick="saveTerminal()">Save Terminal Config</button>
          <span class="form-status" id="terminal-status"></span>
        </div>
        <div class="panel">
          <div class="panel-title tip" data-tip="Schedule recurring tasks. The agent will execute the prompt at the specified interval or cron expression.">Cron — Scheduled Tasks</div>
          <div id="cron-list" style="margin-bottom:12px"><div class="empty">No scheduled tasks</div></div>
          <div style="border-top:1px solid var(--border);padding-top:10px">
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;font-weight:600">Add Scheduled Task</div>
            <div class="form-row"><label class="form-label tip" data-tip="Unique name for this scheduled task. Used to identify and manage it.">Name</label><input class="form-input" id="cron-name" placeholder="daily-report"></div>
            <div class="form-row"><label class="form-label tip" data-tip="Cron expression (e.g. '0 9 * * *' = daily at 9am) or interval shorthand (e.g. '30m' = every 30 minutes).">Schedule</label><input class="form-input" id="cron-schedule" placeholder="0 9 * * * (cron) or 30m (interval)"></div>
            <div class="form-row"><label class="form-label tip" data-tip="The instruction sent to the agent when the task fires. Treated as a user message through the full security pipeline.">Prompt</label><textarea class="form-textarea" id="cron-prompt" rows="2" placeholder="What should Odin do? e.g. Check my emails and summarize them"></textarea></div>
            <button class="btn-action" onclick="addCronJob()">Add Task</button>
            <span class="form-status" id="cron-status"></span>
          </div>
        </div>
      </div>
    </div>

    <!-- SECTION: SECURITY -->
    <div class="section" id="sec-security">
      <div class="two-col">
        <div class="panel">
          <div class="panel-title tip" data-tip="Weighted trust score: Performance 30%, Security 25%, Transparency 15%, Compliance 15%, Reputation 10%, Reliability 5%. Decays over time (7-day half-life).">Trust Score AgentLayers — 6 Dimensions</div>
          <div class="donut-wrapper">
            <div class="donut-container"><canvas id="donut-chart"></canvas>
              <div class="donut-center"><div class="donut-score" id="d-score">82</div><div class="donut-label">/ 100</div></div>
            </div>
            <div>
              <div class="header-badge badge-safe" id="d-badge" style="margin-bottom:6px">SAFE</div>
              <div style="font-size:10px;color:var(--text-dim)" id="d-cert">self:local-baseline</div>
              <div style="font-size:10px;color:var(--text-muted);margin-top:3px" id="d-next">Next eval: 4h 32m</div>
            </div>
          </div>
          <div id="dim-bars"></div>
          <div class="chart-box"><canvas id="hist-chart"></canvas></div>
        </div>
        <div class="panel">
          <div class="panel-title tip" data-tip="4 security layers protecting every tool call: IFC taint tracking, Supply Chain integrity (Merkle+Ed25519), Cedar Policy Engine, and Trust Mesh (IATP).">Couches AEGIS</div>
          <div id="aegis-list"></div>
          <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border)">
            <div class="tip" data-tip="5-state circuit breaker: CLOSED (normal) → DEGRADED (partial failures) → OPEN (blocked) → HALF_OPEN (testing recovery). Innovation: semantic failure detection counts hallucinated 200 OK as double failure." style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);margin-bottom:8px">Circuit Breaker — 5 états</div>
            <div class="cb-row" id="cb-row"></div>
          </div>
        </div>
      </div>
      <div class="two-col">
        <div class="panel">
          <div class="panel-title tip" data-tip="Cryptographically signed log of every security decision (ALLOW/WARN/BLOCK). Each entry is signed with the agent's Ed25519 key for tamper-proof auditing.">Decision Trace — Journal signé DID</div>
          <div class="trace-list" id="trace-list"></div>
        </div>
        <div>
          <div class="panel">
            <div class="panel-title tip" data-tip="Compliance scores against 4 frameworks: EU AI Act (transparency, human oversight), OWASP ASI (top 10 AI risks), Singapore MGF (governance), SLSA (supply chain).">Conformité réglementaire</div>
            <div id="comp-bars"></div>
          </div>
          <div class="panel">
            <div class="panel-title tip" data-tip="Real-time performance metrics computed from actual measurements. Cedar latency, task completion rate, token overhead, and Merkle verification time.">Performance</div>
            <div class="perf-grid" id="perf-grid"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- SECTION: CHAT -->
    <div class="section" id="sec-chat">
      <div class="chat-section">
        <div class="chat-messages" id="chat-messages">
          <div class="chat-empty">
            <div class="chat-empty-icon">⚡</div>
            <div class="chat-empty-title">Chat with Odin</div>
            <div class="chat-empty-sub">Zero Trust AI Agent — Secured by design.<br>Every message passes through IFC, Cedar, and Merkle verification.</div>
          </div>
        </div>
        <div class="chat-input-row">
          <textarea class="chat-input" id="chat-input" placeholder="Message Odin..." rows="1"></textarea>
          <button class="chat-send" id="chat-send">Send</button>
        </div>
      </div>
    </div>

  </div>
</div>

<!-- ─── RIGHT PANEL: ALERTS ─── -->
<aside class="right-panel">
  <div class="right-header">
    <div class="right-title">Recent Alerts</div>
    <button class="btn-clear" id="btn-clear">Clear</button>
  </div>
  <div class="right-list" id="alerts-list">
    <div class="right-empty">No recent warnings or errors.<br>The activity stream is currently healthy.</div>
  </div>
</aside>

</div>

<script>
function escHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// ─── Skill Install ───
async function installSkill() {
  const name = document.getElementById('skill-name').value.trim();
  const desc = document.getElementById('skill-desc').value.trim();
  const paramsRaw = document.getElementById('skill-params').value.trim();
  const code = document.getElementById('skill-code').value.trim();
  const perms = document.getElementById('skill-perms').value.split(',').map(s => s.trim()).filter(Boolean);
  const ring = parseInt(document.getElementById('skill-ring').value);
  const status = document.getElementById('skill-status');

  if (!name || !desc || !code) { status.textContent = 'Name, description, and code are required'; status.className = 'form-status form-err'; return; }

  let params = {};
  if (paramsRaw) { try { params = JSON.parse(paramsRaw); } catch { status.textContent = 'Invalid JSON in parameters'; status.className = 'form-status form-err'; return; } }

  status.textContent = 'Installing...'; status.className = 'form-status';
  try {
    const res = await fetch('/api/skill/install', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description: desc, code, permissions: perms, parameters: params, ring }) });
    const data = await res.json();
    status.textContent = data.message; status.className = data.success ? 'form-status form-ok' : 'form-status form-err';
    if (data.success) { document.getElementById('skill-name').value = ''; document.getElementById('skill-desc').value = '';
      document.getElementById('skill-params').value = ''; document.getElementById('skill-code').value = ''; document.getElementById('skill-perms').value = ''; }
  } catch (err) { status.textContent = 'Connection error'; status.className = 'form-status form-err'; }
}

// ─── MCP Connect ───
async function connectMCP() {
  const name = document.getElementById('mcp-name').value.trim();
  const url = document.getElementById('mcp-url').value.trim();
  const status = document.getElementById('mcp-status');

  if (!name || !url) { status.textContent = 'Name and URL are required'; status.className = 'form-status form-err'; return; }

  status.textContent = 'Connecting...'; status.className = 'form-status';
  try {
    const res = await fetch('/api/mcp/connect', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, url }) });
    const data = await res.json();
    status.textContent = data.message; status.className = data.success ? 'form-status form-ok' : 'form-status form-err';
    if (data.success) { document.getElementById('mcp-name').value = ''; document.getElementById('mcp-url').value = ''; }
  } catch (err) { status.textContent = 'Connection error'; status.className = 'form-status form-err'; }
}

// ─── Config Update ───
async function updateConfig() {
  const provider = document.getElementById('cfg-provider').value;
  const model = document.getElementById('cfg-model').value.trim();
  const apiKey = document.getElementById('cfg-apikey').value.trim();
  const temp = document.getElementById('cfg-temp').value;
  const tokens = document.getElementById('cfg-tokens').value;
  const baseUrl = document.getElementById('cfg-url').value.trim();
  const status = document.getElementById('cfg-status');

  const config = {};
  if (provider) config.provider = provider;
  if (model) config.model = model;
  if (apiKey) config.apiKey = apiKey;
  if (temp) config.temperature = parseFloat(temp);
  if (tokens) config.maxTokens = parseInt(tokens);
  if (baseUrl) config.baseUrl = baseUrl;

  if (Object.keys(config).length === 0) { status.textContent = 'Nothing to update'; status.className = 'form-status form-err'; return; }

  status.textContent = 'Applying...'; status.className = 'form-status';
  try {
    const res = await fetch('/api/config/update', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config) });
    const data = await res.json();
    status.textContent = data.message; status.className = data.success ? 'form-status form-ok' : 'form-status form-err';
    if (data.success) { document.getElementById('cfg-provider').value = ''; document.getElementById('cfg-model').value = '';
      document.getElementById('cfg-apikey').value = ''; document.getElementById('cfg-temp').value = '';
      document.getElementById('cfg-tokens').value = ''; document.getElementById('cfg-url').value = ''; }
  } catch (err) { status.textContent = 'Connection error'; status.className = 'form-status form-err'; }
}

// ─── Generic Settings Save ───
async function saveSetting(section, data) {
  const statusEl = document.getElementById(section + '-status');
  if (statusEl) { statusEl.textContent = 'Saving...'; statusEl.className = 'form-status'; }
  try {
    const res = await fetch('/api/settings/' + section, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
    const result = await res.json();
    if (statusEl) { statusEl.textContent = result.message; statusEl.className = result.success ? 'form-status form-ok' : 'form-status form-err'; }
  } catch (err) { if (statusEl) { statusEl.textContent = 'Connection error'; statusEl.className = 'form-status form-err'; } }
}

async function saveGateway() {
  await saveSetting('gateway', {
    type: document.getElementById('gw-type').value,
    telegramToken: document.getElementById('gw-telegram').value || undefined,
    discordToken: document.getElementById('gw-discord').value || undefined,
    slackToken: document.getElementById('gw-slack').value || undefined,
    allowedUsers: document.getElementById('gw-users').value.split(',').map(s => s.trim()).filter(Boolean),
    requireMention: document.getElementById('gw-mention').value === 'true',
  });
}

async function saveSecurity() {
  await saveSetting('security', {
    approvalMode: document.getElementById('sec-approval').value,
    redactSecrets: document.getElementById('sec-redact').value === 'true',
    maxDailyCalls: parseInt(document.getElementById('sec-maxcalls').value) || undefined,
    sessionTtlSeconds: parseInt(document.getElementById('sec-ttl').value) || undefined,
    websiteBlocklist: document.getElementById('sec-blocklist').value.split(',').map(s => s.trim()).filter(Boolean),
    requireHumanApproval: document.getElementById('sec-tools').value.split(',').map(s => s.trim()).filter(Boolean),
  });
}

async function saveTerminal() {
  await saveSetting('terminal', {
    backend: document.getElementById('term-backend').value,
    timeout: parseInt(document.getElementById('term-timeout').value) || undefined,
    dockerImage: document.getElementById('term-docker').value || undefined,
    sshHost: document.getElementById('term-ssh-host').value || undefined,
    sshPort: parseInt(document.getElementById('term-ssh-port').value) || undefined,
  });
}

async function addCronJob() {
  const name = document.getElementById('cron-name').value.trim();
  const schedule = document.getElementById('cron-schedule').value.trim();
  const prompt = document.getElementById('cron-prompt').value.trim();
  if (!name || !schedule || !prompt) { document.getElementById('cron-status').textContent = 'All fields required'; document.getElementById('cron-status').className = 'form-status form-err'; return; }
  await saveSetting('cron', { action: 'add', name, schedule, prompt });
  document.getElementById('cron-name').value = ''; document.getElementById('cron-schedule').value = ''; document.getElementById('cron-prompt').value = '';
}

let S = {};
const ws = new WebSocket('ws://'+location.host);
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.type==='state-update'){S=m.data;render();} if(m.type==='activity'){addAct(m.data);} };

// UTC clock
setInterval(()=>{document.getElementById('utc-clock').textContent=new Date().toISOString().replace('T',' ').slice(0,19)+' UTC';},1000);
document.getElementById('utc-clock').textContent=new Date().toISOString().replace('T',' ').slice(0,19)+' UTC';

// Navigation
document.querySelectorAll('.nav-item').forEach(el=>{el.addEventListener('click',()=>{
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));el.classList.add('active');
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
  document.getElementById('sec-'+el.dataset.section).classList.add('active');
  const titles={home:'Operations Overview',activity:'Activity Feed',system:'System Configuration',security:'Security — AEGIS'};
  document.getElementById('section-title').textContent=titles[el.dataset.section]||'';
});});

// Clear alerts
document.getElementById('btn-clear').addEventListener('click',()=>{if(S.alerts)S.alerts.forEach(a=>a.acknowledged=true);render();});

// Charts
let donutC, histC;
function initCharts(){
  donutC=new Chart(document.getElementById('donut-chart'),{type:'doughnut',data:{datasets:[{data:[82,18],backgroundColor:['#1D9E75','#30363D'],borderWidth:0}]},options:{cutout:'78%',responsive:true,maintainAspectRatio:true,plugins:{legend:{display:false},tooltip:{enabled:false}}}});
  histC=new Chart(document.getElementById('hist-chart'),{type:'line',data:{labels:[],datasets:[{data:[],borderColor:'#1D9E75',backgroundColor:'rgba(29,158,117,.08)',fill:true,tension:.3,pointRadius:3,pointBackgroundColor:'#1D9E75',borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,scales:{y:{min:0,max:100,grid:{color:'#30363D'},ticks:{color:'#8B949E',font:{family:"var(--mono)",size:10}}},x:{grid:{display:false},ticks:{color:'#8B949E',font:{family:"var(--mono)",size:10}}}},plugins:{legend:{display:false}}}});
}

function sc(v){return v>=75?'g':v>=50?'o':'r';}
function scCol(v){return v>=75?'var(--green)':v>=50?'var(--orange)':'var(--red)';}

function render(){
  if(!S.did) return;
  // Sidebar
  document.getElementById('sb-did').textContent=S.did;
  // Header
  const dot=document.getElementById('gw-dot');dot.className='status-dot status-'+(S.gatewayStatus||'connected');
  document.getElementById('gw-info').textContent=(S.gatewayStatus==='connected'?'Gateway connected':'Gateway OFFLINE')+' · DID actif';
  const hb=document.getElementById('hd-badge');hb.textContent=S.trustMode;hb.className='header-badge badge-'+S.trustMode.toLowerCase();

  // KPIs
  const kpis=[
    {l:'Trust Score',v:S.trustScore,s:(S.trustScoreDelta>=0?'+':'')+S.trustScoreDelta+' vs hier',c:S.trustScoreDelta>=0?'kpi-up':'kpi-down',t:'Composite score (0-100) from 6 dimensions. Decays over time. Below 40 = DEGRADED mode.'},
    {l:'Sessions',v:S.activeSessions,s:S.tokensToday+' tokens today',t:'Active chat sessions and total LLM tokens consumed today.'},
    {l:'Channels',v:S.channels+'/1',s:'CLI active',t:'Connected messaging channels (CLI, Telegram, Discord, Slack).'},
    {l:'Agents',v:S.agentsConnected,s:S.agentsCertified+' certified',t:'Peer agents connected via A2A protocol. Certified = verified by AgentLayers.'},
    {l:'Alerts',v:S.alertsActive,s:S.alertsCritical+' critical · '+S.alertsWarning+' warn',c:S.alertsActive>0?'kpi-down':'',t:'Active security alerts from IFC violations, Cedar blocks, and trust warnings.'},
  ];
  document.getElementById('kpi-row').innerHTML=kpis.map(k=>'<div class="kpi tip" data-tip="'+escHtml(k.t)+'"><div class="kpi-label">'+escHtml(k.l)+'</div><div class="kpi-val"'+(k.c?' style="color:'+scCol(k.v)+'"':'')+'>'+escHtml(String(k.v))+'</div><div class="kpi-sub'+(k.c?' '+k.c:'')+'">'+escHtml(k.s)+'</div></div>').join('');

  // Health cards
  const hc=[
    {name:'Gateway',live:'green',rows:[['Status',S.gatewayStatus],['DID',S.did.slice(0,24)+'...'],['IFC Engine','ACTIVE'],['Cedar PEP','< 0.1ms']],link:'system',t:'Input gateway status. Shows DID identity, IFC taint engine, and Cedar policy enforcement point latency.'},
    {name:'Agents',live:S.agentsConnected>0?'green':'green',rows:[['Active',S.agentsConnected],['Certified',S.agentsCertified],['Quarantined',S.peerAgents.filter(a=>a.status==='quarantined').length],['Avg Trust',S.peerAgents.length?Math.round(S.peerAgents.reduce((a,b)=>a+b.trustScore,0)/S.peerAgents.length):'N/A']],link:'security',t:'A2A peer agents. Connected via signed messages. Circuit breaker isolates unreliable peers.'},
    {name:'Sessions',live:'green',rows:[['Active',S.activeSessions],['Model',S.llmModel],['Tokens today',S.tokensToday],['Uptime',S.uptime]],link:'activity',t:'Current LLM session info. Token usage, model, and agent uptime since last restart.'},
    {name:'Skills',live:'green',rows:[['Installed',S.skillsInstalled],['Tier 1+',S.skillsTier1Plus],['Tier 0',S.skillsTier0],['Built-in',S.skills.filter(s=>s.status==='built-in').length]],link:'system',t:'Installed tools/skills by trust tier. T0=unscanned, T1+=verified by AgentLayers, Built-in=core tools.'},
    {name:'Alert Pressure',live:S.alertsActive>0?'orange':'green',rows:[['Active',S.alertsActive],['Cedar violations',S.alertsCritical],['Trust warnings',S.alertsWarning],['IFC blocks',S.decisionTrace.filter(d=>d.type==='block'&&d.emitter==='IFC Engine').length]],link:'security',t:'Security pressure gauge. High alert count degrades trust score and may trigger DEGRADED mode.'},
  ];
  document.getElementById('health-grid').innerHTML=hc.map(c=>'<div class="health-card" onclick="navTo(\\''+c.link+'\\')"><div class="health-top"><div class="health-name">'+escHtml(c.name)+'</div><span class="live-badge live-'+c.live+'">LIVE</span></div><div class="health-rows">'+c.rows.map(r=>'<div class="health-row"><span class="health-row-label">'+escHtml(String(r[0]))+'</span><span class="health-row-val">'+escHtml(String(r[1]))+'</span></div>').join('')+'</div><span class="health-open">Open →</span></div>').join('');
  document.querySelectorAll('.health-card').forEach((el,i)=>{el.setAttribute('title',hc[i].t);});

  // Topology
  document.getElementById('topo-graph').innerHTML=
    '<div class="topo-node"><div class="topo-circle topo-circle-green">⚡</div><div class="topo-label">Odin Agent</div><div class="topo-sub">'+escHtml(S.trustMode)+'</div></div>'
    +'<div class="topo-edge"><span class="topo-edge-label">IFC + Cedar</span></div>'
    +'<div class="topo-node"><div class="topo-circle topo-circle-blue">◈</div><div class="topo-label">CLI Gateway</div><div class="topo-sub">'+escHtml(S.gatewayStatus)+'</div></div>'
    +(S.peerAgents.length?S.peerAgents.map(a=>'<div class="topo-edge"><span class="topo-edge-label">trust:'+escHtml(String(a.trustScore))+'</span></div><div class="topo-node"><div class="topo-circle" style="border-color:'+scCol(a.trustScore)+'">◎</div><div class="topo-label">'+escHtml(a.name)+'</div><div class="topo-sub">'+escHtml(String(a.trustScore))+'</div></div>').join(''):'');
  document.getElementById('topo-bar').innerHTML=
    ['SYSTEM:HEALTHCHECK','SECURITY:SELF-AUDIT','MERKLE:VERIFY','TRUST:DECAY'].map(j=>'<div class="topo-job">'+j+'</div>').join('');

  // Activity
  renderActivity();

  // System
  document.getElementById('sys-llm').innerHTML=[['Model',S.llmModel],['Provider',S.llmProvider==='none'?'Not configured':S.llmProvider],['Pattern','Dual-LLM (CaMeL)'],['Max Tokens',String(S.llmMaxTokens)],['Temperature',String(S.llmTemperature)]].map(r=>'<div class="health-row"><span class="health-row-label">'+escHtml(r[0])+'</span><span class="health-row-val">'+escHtml(r[1])+'</span></div>').join('');
  document.getElementById('sys-skills').innerHTML=S.skills.map(s=>'<tr><td style="font-family:var(--mono)">'+escHtml(s.name)+' <span style="color:var(--text-dim)">'+escHtml(s.version)+'</span></td><td><span class="tier t'+s.tier+'">T'+s.tier+'</span></td><td style="font-family:var(--mono);color:var(--text-muted)">R'+s.ring+'</td><td style="font-family:var(--mono)">'+(s.score!=null?escHtml(String(s.score)):'—')+'</td></tr>').join('');
  document.getElementById('sys-mcp').innerHTML=S.mcpServers.length?'<table class="tbl"><thead><tr><th>Server</th><th>Status</th><th>Score</th></tr></thead><tbody>'+S.mcpServers.map(m=>'<tr><td style="font-family:var(--mono)">'+escHtml(m.name)+'</td><td><span class="mcp-st" style="background:var(--'+{SAFE:'green',CAUTION:'orange',DANGEROUS:'red'}[m.status]+'-bg);color:var(--'+{SAFE:'green',CAUTION:'orange',DANGEROUS:'red'}[m.status]+')">'+escHtml(m.status)+'</span></td><td style="font-family:var(--mono)">'+escHtml(String(m.score))+'</td></tr>').join('')+'</tbody></table>':'<div class="empty">No MCP servers connected</div>';

  // Security — Trust Score
  document.getElementById('d-score').textContent=S.trustScore;
  donutC.data.datasets[0].data=[S.trustScore,100-S.trustScore];
  donutC.data.datasets[0].backgroundColor[0]=sc(S.trustScore)==='g'?'#1D9E75':sc(S.trustScore)==='o'?'#D29922':'#F85149';
  donutC.update();
  const db=document.getElementById('d-badge');db.textContent=S.trustMode;db.className='header-badge badge-'+S.trustMode.toLowerCase();
  document.getElementById('d-cert').textContent=escHtml(S.certifiedBy);
  document.getElementById('d-next').textContent='Next eval: '+escHtml(S.nextEvaluation);

  const dimN={performance:'Performance (20%)',transparency:'Transparence (20%)',security:'Sécurité & Privacy (20%)',compliance:'Conformité (15%)',reputation:'Réputation (15%)',reliability:'Fiabilité comp. (10%)'};
  document.getElementById('dim-bars').innerHTML=Object.entries(dimN).map(([k,l])=>{const v=S.dimensions[k];return '<div class="dim-row"><div class="dim-name">'+escHtml(l)+'</div><div class="dim-bar"><div class="dim-fill fill-'+sc(v)+'" style="width:'+v+'%"></div></div><div class="dim-val" style="color:'+scCol(v)+'">'+escHtml(String(v))+'</div></div>';}).join('');

  histC.data.labels=S.trustHistory.map(h=>h.date.slice(5));
  histC.data.datasets[0].data=S.trustHistory.map(h=>h.score);histC.update();

  // AEGIS
  document.getElementById('aegis-list').innerHTML=S.aegisLayers.map(l=>{const st=l.status.toLowerCase();return '<div class="aegis"><div class="aegis-header"><div class="aegis-dot dot-'+st+'"></div><div class="aegis-info"><div class="aegis-name">'+escHtml(l.name)+'</div><div class="aegis-desc">'+escHtml(l.description)+'</div></div><div class="st-badge st-'+st+'">'+escHtml(l.status)+'</div></div><div class="aegis-footer"><div class="aegis-metric">'+escHtml(l.metric)+'</div><div class="aegis-tags">'+l.owaspRisks.map(r=>'<span class="aegis-tag">'+escHtml(r)+'</span>').join('')+'</div></div></div>';}).join('');

  // CB
  const cbs=['CLOSED','DEGRADED','OPEN','HALF_OPEN'];
  document.getElementById('cb-row').innerHTML=cbs.map((s,i)=>{let cls='cb';if(S.circuitBreakerState===s){cls+=' cb-active';if(s==='DEGRADED')cls+=' cb-deg';if(s==='OPEN')cls+=' cb-open';if(s==='HALF_OPEN')cls+=' cb-half';}return (i>0?'<span class="cb-arrow">→</span>':'')+'<div class="'+cls+'">'+s.replace('_','-')+'</div>';}).join('');

  // Decision Trace
  if(!S.decisionTrace.length){document.getElementById('trace-list').innerHTML='<div class="empty">Waiting for decisions...</div>';}
  else{document.getElementById('trace-list').innerHTML=S.decisionTrace.slice(0,50).map(t=>'<div class="trace"><div class="trace-time">'+escHtml(t.timestamp)+'</div><div class="trace-dot td-'+t.type+'"></div><div><span class="trace-em">'+escHtml(t.emitter)+'</span> <span class="trace-det">'+escHtml(t.action)+'</span><br><span class="trace-layer">'+escHtml(t.layer)+'</span> '+escHtml(t.detail)+'</div></div>').join('');}

  // Compliance
  const cd=[{n:'EU AI Act — Art. 50',v:S.compliance.euAiAct,d:S.compliance.euAiAct+'%'},{n:'OWASP ASI 2026',v:parseInt(S.compliance.owaspAsi)*10,d:S.compliance.owaspAsi},{n:'Singapore MGF',v:S.compliance.singaporeMgf,d:S.compliance.singaporeMgf+'%'},{n:'SLSA Provenance',v:S.compliance.slsa,d:S.compliance.slsa+'%'}];
  document.getElementById('comp-bars').innerHTML=cd.map(c=>'<div class="comp-row"><div class="comp-name">'+escHtml(c.n)+'</div><div class="comp-bar"><div class="comp-fill fill-'+sc(c.v)+'" style="width:'+c.v+'%"></div></div><div class="comp-val" style="color:'+scCol(c.v)+'">'+escHtml(c.d)+'</div></div>').join('');

  // Perf
  const pd=[{l:'Latency / tool call',v:S.performance.latencyMs+' ms',t:'< 10 ms'},{l:'Task completion',v:S.performance.taskCompletion+'%',t:'≥ 75%'},{l:'Token overhead',v:S.performance.tokenOverhead+'×',t:'< 3×'},{l:'Merkle verify',v:S.performance.merkleVerifyMs+' ms',t:'< 500 ms'}];
  document.getElementById('perf-grid').innerHTML=pd.map(p=>'<div class="perf"><div class="perf-label">'+escHtml(p.l)+'</div><div class="perf-val">'+escHtml(p.v)+'</div><div class="perf-target">Target: '+escHtml(p.t)+'</div></div>').join('');

  // Alerts panel
  renderAlerts();

  // Recent chats in sidebar
  const rc = S.recentChats || [];
  if (rc.length === 0) {
    document.getElementById('recent-chats').innerHTML = '<div class="chat-item" style="color:var(--text-dim)">No conversations yet</div>';
  } else {
    document.getElementById('recent-chats').innerHTML = rc.map(c =>
      '<div class="chat-item" onclick="document.getElementById(\\'btn-new-chat\\').click()">' + escHtml(c.title) + '<br><span style="font-size:9px;color:var(--text-dim)">' + escHtml(c.timestamp) + '</span></div>'
    ).join('');
  }
}

function renderAlerts(){
  const al=(S.alerts||[]).filter(a=>!a.acknowledged);
  if(!al.length){document.getElementById('alerts-list').innerHTML='<div class="right-empty">No recent warnings or errors.<br>The activity stream is currently healthy.</div>';return;}
  document.getElementById('alerts-list').innerHTML=al.map(a=>'<div class="alert-item" onclick="ackAlert(\\''+a.id+'\\')"><div class="alert-top"><div class="alert-sev sev-'+a.severity+'"></div><div class="alert-source">'+escHtml(a.source)+'</div><div class="alert-time">'+escHtml(a.timestamp)+'</div></div><div class="alert-msg">'+escHtml(a.message)+'</div></div>').join('');
}

function renderActivity(){
  const acts=S.activities||[];
  if(!acts.length){document.getElementById('activity-list').innerHTML='<div class="empty">No activity recorded yet</div>';return;}
  document.getElementById('activity-list').innerHTML=acts.slice(0,50).map(a=>{
    const tc={tool_call:'act-tool',chat:'act-chat',a2a:'act-a2a',security:'act-sec'}[a.type]||'act-tool';
    return '<div class="act"><div class="act-time">'+escHtml(a.timestamp)+'</div><div class="act-type '+tc+'">'+escHtml(a.type.replace('_',' '))+'</div><div class="act-info"><div class="act-action">'+escHtml(a.action)+'</div><div class="act-detail">'+escHtml(a.detail)+(a.tokens?' · '+a.tokens+' tokens':'')+(a.duration?' · '+escHtml(a.duration):'')+'</div></div></div>';
  }).join('');
}

function addAct(a){S.activities=S.activities||[];S.activities.unshift(a);renderActivity();}
function navTo(sec){document.querySelector('.nav-item[data-section="'+sec+'"]').click();}
function ackAlert(id){if(S.alerts){const a=S.alerts.find(x=>x.id===id);if(a)a.acknowledged=true;S.alertsActive=(S.alerts||[]).filter(a=>!a.acknowledged).length;render();}}

initCharts();

// ─── Chat UI ───
const chatInput = document.getElementById('chat-input');
const chatSend = document.getElementById('chat-send');
const chatMessages = document.getElementById('chat-messages');
let chatHasMessages = false;

document.getElementById('btn-new-chat').addEventListener('click', () => {
  // Switch to chat section
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.getElementById('sec-chat').classList.add('active');
  document.getElementById('section-title').textContent = 'Chat with Odin';
  chatInput.focus();
});

async function sendChat() {
  const msg = chatInput.value.trim();
  if (!msg) return;
  chatInput.value = '';
  chatInput.style.height = 'auto';
  chatSend.disabled = true;

  // Clear empty state on first message
  if (!chatHasMessages) { chatMessages.innerHTML = ''; chatHasMessages = true; }

  // Add user message
  chatMessages.innerHTML += '<div class="chat-msg chat-msg-user"><div class="chat-avatar chat-avatar-user">U</div><div class="chat-bubble chat-bubble-user">' + escHtml(msg) + '</div></div>';

  // Add typing indicator
  const typingId = 'typing-' + Date.now();
  chatMessages.innerHTML += '<div class="chat-msg chat-msg-agent" id="' + typingId + '"><div class="chat-avatar chat-avatar-agent">⚡</div><div class="chat-bubble chat-bubble-agent"><div class="typing-dots"><span></span><span></span><span></span></div></div></div>';
  chatMessages.scrollTop = chatMessages.scrollHeight;

  const t0 = performance.now();
  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg }),
    });
    const data = await res.json();
    const elapsed = ((performance.now() - t0) / 1000).toFixed(1);

    // Remove typing indicator
    const typing = document.getElementById(typingId);
    if (typing) typing.remove();

    if (data.error) {
      chatMessages.innerHTML += '<div class="chat-msg chat-msg-agent"><div class="chat-avatar chat-avatar-agent">⚡</div><div class="chat-bubble chat-bubble-agent" style="border-color:var(--red);color:var(--red)">Error: ' + escHtml(data.error) + '</div></div>';
    } else {
      chatMessages.innerHTML += '<div class="chat-msg chat-msg-agent"><div class="chat-avatar chat-avatar-agent">⚡</div><div class="chat-bubble chat-bubble-agent">' + escHtml(data.reply) + '<div class="chat-meta"><span>' + elapsed + 's</span><span>IFC ✓</span><span>Cedar ✓</span><span>Merkle ✓</span></div></div></div>';
    }
  } catch (err) {
    const typing = document.getElementById(typingId);
    if (typing) typing.remove();
    chatMessages.innerHTML += '<div class="chat-msg chat-msg-agent"><div class="chat-avatar chat-avatar-agent">⚡</div><div class="chat-bubble chat-bubble-agent" style="border-color:var(--red);color:var(--red)">Connection error: ' + escHtml(err.message || 'Failed to reach agent') + '</div></div>';
  }

  chatMessages.scrollTop = chatMessages.scrollHeight;
  chatSend.disabled = false;
  chatInput.focus();
}

chatSend.addEventListener('click', sendChat);
chatInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); }
});
// Auto-resize textarea
chatInput.addEventListener('input', () => {
  chatInput.style.height = 'auto';
  chatInput.style.height = Math.min(chatInput.scrollHeight, 120) + 'px';
});

<\/script>
</body>
</html>`;

export default DashboardServer;
