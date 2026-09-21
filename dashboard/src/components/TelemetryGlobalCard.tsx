/**
 * TelemetryGlobalCard — Vista global de tráfico en vivo del pipeline Wazuh.
 *
 * Muestra:
 *  - Indicador LIVE / POLLING / OFFLINE
 *  - KPIs: recibidas, enviadas, deduplicadas, errores WAHA, latencia avg
 *  - Sparkline ASCII de actividad últimos 60 segundos (CSS puro, sin libs)
 *  - Feed de últimas alertas en vivo (scrollable)
 *  - Top 5 reglas más disparadas
 *  - Top 5 agentes con más actividad
 */

import React, { useState } from 'react';
import { useTelemetry } from '../hooks/useTelemetry';
import type { LiveAlertEntry } from '../types/telemetry';
import {
  Radio,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Minus,
  Activity,
  Zap,
  RefreshCw,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';

/* ── Utilidades ─────────────────────────────────────────────────────────── */

const SPARKLINE_CHARS = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

function toSparkline(histogram: number[]): string {
  const max = Math.max(...histogram, 1);
  return histogram
    .map((v) => {
      const idx = Math.min(
        Math.floor((v / max) * (SPARKLINE_CHARS.length - 1)),
        SPARKLINE_CHARS.length - 1,
      );
      return v === 0 ? '▁' : SPARKLINE_CHARS[idx];
    })
    .join('');
}

function formatNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function timeSince(ts: number): string {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 5) return 'ahora';
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  return `${Math.floor(diff / 3600)}h`;
}

const DECISION_COLOR: Record<string, string> = {
  sent: 'var(--green-healthy)',
  deduped: 'var(--text-secondary)',
  format_error: 'var(--yellow-warning)',
  waha_error: 'var(--red-error)',
};

const DECISION_LABEL: Record<string, string> = {
  sent: 'Enviada',
  deduped: 'Dedup',
  format_error: 'Error fmt',
  waha_error: 'Error WAHA',
};

const LEVEL_COLOR = (level: number): string => {
  if (level >= 12) return 'var(--red-error)';
  if (level >= 8) return 'var(--yellow-warning)';
  return 'var(--text-secondary)';
};

/* ── KPI Card ────────────────────────────────────────────────────────────── */
interface KpiCardProps {
  label: string;
  value: string;
  sub?: string;
  color?: string;
  icon: React.ReactNode;
}
const KpiCard: React.FC<KpiCardProps> = ({ label, value, sub, color, icon }) => (
  <div
    style={{
      background: 'var(--bg-card-hover)',
      border: '1px solid var(--border-subtle)',
      borderRadius: '10px',
      padding: '14px 16px',
      display: 'flex',
      flexDirection: 'column',
      gap: '6px',
      minWidth: 0,
    }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)', fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
      {icon}
      <span>{label}</span>
    </div>
    <div style={{ fontSize: '24px', fontWeight: 700, color: color ?? 'var(--text-primary)', fontVariantNumeric: 'tabular-nums' }}>
      {value}
    </div>
    {sub && <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{sub}</div>}
  </div>
);

/* ── Sparkline Bar ───────────────────────────────────────────────────────── */
const SparklineBar: React.FC<{ histogram: number[] }> = ({ histogram }) => {
  const max = Math.max(...histogram, 1);
  const last60 = histogram.slice(-60);

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-end',
        gap: '1px',
        height: '40px',
        padding: '0 2px',
      }}
      title={`Pico: ${max} alertas/s`}
    >
      {last60.map((v, i) => {
        const pct = v / max;
        const heightPx = Math.max(pct * 40, v > 0 ? 3 : 1);
        const hue = pct > 0.8 ? 'var(--red-error)' : pct > 0.5 ? 'var(--yellow-warning)' : 'var(--cyan-accent)';
        return (
          <div
            key={i}
            title={`${v} alertas`}
            style={{
              width: '3px',
              height: `${heightPx}px`,
              background: v === 0 ? 'var(--border-subtle)' : hue,
              borderRadius: '1px',
              opacity: v === 0 ? 0.3 : 0.85,
              transition: 'height 0.3s ease',
              flexShrink: 0,
            }}
          />
        );
      })}
    </div>
  );
};

/* ── AlertRow ────────────────────────────────────────────────────────────── */
const AlertRow: React.FC<{ alert: LiveAlertEntry }> = ({ alert }) => (
  <div
    style={{
      display: 'grid',
      gridTemplateColumns: '36px 48px 90px 1fr 64px 48px',
      gap: '8px',
      alignItems: 'center',
      padding: '5px 8px',
      borderBottom: '1px solid rgba(255,255,255,0.03)',
      fontSize: '11px',
    }}
  >
    <span style={{ color: LEVEL_COLOR(alert.level), fontWeight: 700 }}>
      L{alert.level}
    </span>
    <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
      #{alert.rule_id}
    </span>
    <span
      style={{
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        color: 'var(--text-secondary)',
      }}
      title={alert.agent_name}
    >
      {alert.agent_name || alert.agent_id}
    </span>
    <span
      style={{
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        color: 'var(--text-primary)',
      }}
      title={alert.description}
    >
      {alert.description}
    </span>
    <span
      style={{
        fontSize: '10px',
        padding: '2px 6px',
        borderRadius: '4px',
        background: 'rgba(255,255,255,0.06)',
        color: DECISION_COLOR[alert.decision] ?? 'var(--text-secondary)',
        fontWeight: 600,
        textAlign: 'center',
        whiteSpace: 'nowrap',
      }}
    >
      {DECISION_LABEL[alert.decision] ?? alert.decision}
    </span>
    <span style={{ color: 'var(--text-muted)', textAlign: 'right' }}>
      {timeSince(alert.ts)}
    </span>
  </div>
);

/* ── Main Component ──────────────────────────────────────────────────────── */
export const TelemetryGlobalCard: React.FC = () => {
  const { snapshot, connected, mode, error } = useTelemetry();
  const [expanded, setExpanded] = useState(true);
  const [showFeed, setShowFeed] = useState(false);

  /* ── Estado de conexión badge ── */
  const connectionBadge = () => {
    if (connected && mode === 'sse') {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '11px', fontWeight: 700, color: 'var(--green-healthy)', background: 'rgba(46,204,113,0.12)', border: '1px solid rgba(46,204,113,0.25)', borderRadius: '20px', padding: '3px 10px' }}>
          <Radio size={11} style={{ animation: 'pulse 2s infinite' }} />
          LIVE
        </span>
      );
    }
    if (connected && mode === 'polling') {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '11px', fontWeight: 700, color: 'var(--yellow-warning)', background: 'rgba(241,196,15,0.12)', border: '1px solid rgba(241,196,15,0.25)', borderRadius: '20px', padding: '3px 10px' }}>
          <RefreshCw size={11} />
          POLLING 3s
        </span>
      );
    }
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '11px', fontWeight: 700, color: 'var(--red-error)', background: 'rgba(231,76,60,0.12)', border: '1px solid rgba(231,76,60,0.25)', borderRadius: '20px', padding: '3px 10px' }}>
        <XCircle size={11} />
        OFFLINE
      </span>
    );
  };

  const kpis = snapshot?.kpis;
  const histogram = snapshot?.histogram ?? Array(60).fill(0);
  const topRules = snapshot?.top_rules ?? [];
  const topAgents = snapshot?.top_agents ?? [];
  const alertsLive = snapshot?.alerts_live ?? [];
  const sparkStr = toSparkline(histogram);

  return (
    <div
      style={{
        margin: '0 24px 22px',
        background: 'var(--bg-card)',
        border: '1px solid var(--border-card)',
        borderRadius: '14px',
        overflow: 'hidden',
        boxShadow: connected ? '0 0 0 1px rgba(0,188,212,0.08)' : 'none',
      }}
    >
      {/* ── Header ── */}
      <div
        onClick={() => setExpanded((p) => !p)}
        style={{
          padding: '16px 20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          cursor: 'pointer',
          userSelect: 'none',
          borderBottom: expanded ? '1px solid var(--border-subtle)' : 'none',
          background: expanded ? 'rgba(255,255,255,0.02)' : 'transparent',
          gap: '12px',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '20px' }}>📡</span>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
                Tráfico en Vivo — Pipeline Wazuh
              </h3>
              {connectionBadge()}
            </div>
            <p style={{ margin: '3px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
              {snapshot
                ? `${formatNum(kpis?.total_received ?? 0)} alertas recibidas · ${formatNum(kpis?.alerts_last_60s ?? 0)} últimos 60s`
                : error
                ? `Error: ${error}`
                : 'Conectando al relay...'}
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {snapshot && (
            <span style={{ fontFamily: 'monospace', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '-0.02em' }}>
              {sparkStr}
            </span>
          )}
          {expanded ? <ChevronDown size={16} color="var(--text-secondary)" /> : <ChevronRight size={16} color="var(--text-secondary)" />}
        </div>
      </div>

      {/* ── Body ── */}
      {expanded && (
        <div style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '18px' }}>

          {/* KPIs */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '10px' }}>
            <KpiCard
              label="Recibidas"
              value={formatNum(kpis?.total_received ?? 0)}
              sub="desde startup"
              color="var(--cyan-accent)"
              icon={<Activity size={12} />}
            />
            <KpiCard
              label="Enviadas"
              value={formatNum(kpis?.total_sent ?? 0)}
              sub={`${kpis && kpis.total_received > 0 ? Math.round((kpis.total_sent / kpis.total_received) * 100) : 0}% efectividad`}
              color="var(--green-healthy)"
              icon={<CheckCircle2 size={12} />}
            />
            <KpiCard
              label="Deduplicadas"
              value={formatNum(kpis?.total_deduped ?? 0)}
              sub="filtradas por TTL"
              icon={<Minus size={12} />}
            />
            <KpiCard
              label="Errores WAHA"
              value={formatNum(kpis?.total_waha_errors ?? 0)}
              sub="fallos de envío"
              color={kpis?.total_waha_errors ? 'var(--red-error)' : 'var(--text-secondary)'}
              icon={<AlertTriangle size={12} />}
            />
            <KpiCard
              label="Lat. Promedio"
              value={kpis?.lat_avg_ms != null ? `${kpis.lat_avg_ms}ms` : '—'}
              sub={kpis?.lat_p95_ms != null ? `p95: ${kpis.lat_p95_ms}ms` : 'sin datos'}
              color="var(--wazuh-blue)"
              icon={<Zap size={12} />}
            />
          </div>

          {/* Sparkline de actividad */}
          <div>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Activity size={12} />
              <span>Actividad últimos 60 segundos</span>
              <span style={{ marginLeft: 'auto', fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>
                pico: {Math.max(...histogram)} alert/s
              </span>
            </div>
            <div style={{ background: 'var(--bg-card-hover)', borderRadius: '8px', padding: '10px 12px', border: '1px solid var(--border-subtle)' }}>
              <SparklineBar histogram={histogram} />
            </div>
          </div>

          {/* Top Rules + Top Agents */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px' }}>
            {/* Top Reglas */}
            <div style={{ background: 'var(--bg-card-hover)', borderRadius: '10px', padding: '14px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <AlertTriangle size={12} />
                <span>Top Reglas Disparadas</span>
              </div>
              {topRules.length === 0 ? (
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: 0 }}>Sin actividad registrada aún.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {topRules.slice(0, 5).map((r, i) => {
                    const maxCount = topRules[0]?.count || 1;
                    const pct = Math.round((r.count / maxCount) * 100);
                    return (
                      <div key={r.rule_id}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '3px' }}>
                          <span style={{ display: 'flex', gap: '6px' }}>
                            <span style={{ color: 'var(--text-muted)', width: '14px', textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>{i + 1}.</span>
                            <span style={{ fontFamily: 'monospace', color: 'var(--cyan-accent)' }}>#{r.rule_id}</span>
                          </span>
                          <span style={{ color: 'var(--text-secondary)', fontVariantNumeric: 'tabular-nums' }}>{r.count.toLocaleString()}</span>
                        </div>
                        <div style={{ height: '3px', borderRadius: '2px', background: 'var(--border-subtle)', overflow: 'hidden' }}>
                          <div style={{ width: `${pct}%`, height: '100%', background: 'var(--cyan-accent)', borderRadius: '2px', transition: 'width 0.5s ease' }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Top Agentes */}
            <div style={{ background: 'var(--bg-card-hover)', borderRadius: '10px', padding: '14px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Activity size={12} />
                <span>Top Agentes Activos</span>
              </div>
              {topAgents.length === 0 ? (
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: 0 }}>Sin actividad registrada aún.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {topAgents.slice(0, 5).map((a, i) => {
                    const maxCount = topAgents[0]?.count || 1;
                    const pct = Math.round((a.count / maxCount) * 100);
                    return (
                      <div key={a.agent}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '3px' }}>
                          <span style={{ display: 'flex', gap: '6px' }}>
                            <span style={{ color: 'var(--text-muted)', width: '14px', textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>{i + 1}.</span>
                            <span style={{ color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '140px' }} title={a.agent}>{a.agent}</span>
                          </span>
                          <span style={{ color: 'var(--text-secondary)', fontVariantNumeric: 'tabular-nums' }}>{a.count.toLocaleString()}</span>
                        </div>
                        <div style={{ height: '3px', borderRadius: '2px', background: 'var(--border-subtle)', overflow: 'hidden' }}>
                          <div style={{ width: `${pct}%`, height: '100%', background: 'var(--wazuh-blue)', borderRadius: '2px', transition: 'width 0.5s ease' }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Feed de alertas en vivo */}
          <div>
            <button
              type="button"
              onClick={() => setShowFeed((p) => !p)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--text-secondary)',
                fontSize: '11px',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.07em',
                padding: 0,
                marginBottom: showFeed ? '10px' : 0,
              }}
            >
              {showFeed ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
              <Radio size={12} />
              <span>Feed en Vivo ({alertsLive.length} eventos en buffer)</span>
            </button>

            {showFeed && (
              <div style={{ background: 'var(--bg-card-hover)', borderRadius: '10px', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}>
                {/* Cabecera de tabla */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '36px 48px 90px 1fr 64px 48px',
                    gap: '8px',
                    padding: '6px 8px',
                    background: 'rgba(255,255,255,0.04)',
                    borderBottom: '1px solid var(--border-subtle)',
                    fontSize: '10px',
                    fontWeight: 700,
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                  }}
                >
                  <span>Lvl</span>
                  <span>Regla</span>
                  <span>Agente</span>
                  <span>Descripción</span>
                  <span>Estado</span>
                  <span style={{ textAlign: 'right' }}>Hace</span>
                </div>

                <div style={{ maxHeight: '280px', overflowY: 'auto' }}>
                  {alertsLive.length === 0 ? (
                    <div style={{ padding: '16px', textAlign: 'center', fontSize: '12px', color: 'var(--text-muted)' }}>
                      Sin alertas en el buffer aún. Esperando tráfico de Wazuh...
                    </div>
                  ) : (
                    [...alertsLive].reverse().map((a, i) => (
                      <AlertRow key={`${a.rule_id}-${a.ts}-${i}`} alert={a} />
                    ))
                  )}
                </div>
              </div>
            )}
          </div>

        </div>
      )}
    </div>
  );
};

export default TelemetryGlobalCard;
