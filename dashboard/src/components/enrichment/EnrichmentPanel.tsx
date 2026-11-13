import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  Check,
  ChevronDown,
  Copy,
  Crosshair,
  Globe,
  Info,
  Server,
  ShieldAlert,
  Wrench,
} from 'lucide-react';
import type { Enrichment } from '../../types/telemetry';
import { copyToClipboard } from '../../utils/clipboard';
import './EnrichmentPanel.css';

interface EnrichmentPanelProps {
  enrichment?: Enrichment | null;
  raw?: unknown;
  compact?: boolean;
  defaultTechnical?: boolean;
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'crit',
  high: 'high',
  medium: 'med',
  low: 'low',
  info: 'info',
};

const CRITICALITY_LABEL: Record<string, string> = {
  critical: 'Crítico',
  high: 'Alto',
  medium: 'Medio',
  low: 'Bajo',
};

export const EnrichmentPanel: React.FC<EnrichmentPanelProps> = ({
  enrichment,
  raw,
  compact = false,
  defaultTechnical = false,
}) => {
  const [copied, setCopied] = useState<string | null>(null);
  const [showTechnical, setShowTechnical] = useState(defaultTechnical);

  const severity = enrichment?.risk?.technical_severity || 'info';
  const severityClass = SEVERITY_CLASS[severity] || 'info';
  const summary = enrichment?.translations?.summary_es
    || enrichment?.translations?.description_es
    || '';
  const description = enrichment?.translations?.description_es || '';
  const businessImpact = enrichment?.risk?.business_impact || '';
  const steps = enrichment?.remediation || [];
  const asset = enrichment?.asset;
  const network = enrichment?.network;
  const iocs = enrichment?.iocs || [];
  const tactics = enrichment?.risk?.mitre_tactics || [];
  const techniques = enrichment?.risk?.mitre_techniques || [];

  const rawJson = useMemo(() => {
    if (!raw) return '';
    try {
      return JSON.stringify(raw, null, 2).slice(0, 12000);
    } catch {
      return '';
    }
  }, [raw]);

  const copy = async (text: string, key: string) => {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopied(key);
      window.setTimeout(() => setCopied(null), 1600);
    }
  };

  if (!enrichment) {
    return (
      <div className="enrichment-panel enrichment-empty">
        <Info size={14} />
        <span>Sin explicación enriquecida para este evento.</span>
        {rawJson && (
          <details>
            <summary>Ver datos técnicos</summary>
            <pre>{rawJson}</pre>
          </details>
        )}
      </div>
    );
  }

  return (
    <div className={`enrichment-panel ${compact ? 'compact' : ''}`}>
      <div className="enrich-head">
        <span className={`enrich-severity ${severityClass}`}>
          <ShieldAlert size={13} />
          {enrichment.risk.plain_severity || severity}
        </span>
        {enrichment.degraded && (
          <span className="enrich-badge warn">
            <AlertTriangle size={12} /> Explicación parcial
          </span>
        )}
        <span className="enrich-badge">
          Confianza {Math.round((enrichment.confidence || 0) * 100)}%
        </span>
        {enrichment.risk.sla && (
          <span className="enrich-badge">SLA: {enrichment.risk.sla}</span>
        )}
      </div>

      <div className="enrich-summary">
        {summary || description || 'Evento de seguridad registrado.'}
      </div>

      {!compact && businessImpact && (
        <div className="enrich-block">
          <h5><Info size={13} /> ¿Por qué importa?</h5>
          <p>{businessImpact}</p>
        </div>
      )}

      {steps.length > 0 && (
        <div className="enrich-block">
          <h5><Wrench size={13} /> ¿Qué hacer?</h5>
          <ol className="enrich-steps">
            {steps.slice(0, compact ? 1 : steps.length).map((step) => (
              <li key={`${step.order}-${step.action}`}>
                <div className="enrich-step-main">
                  <strong>{step.action}</strong>
                  {step.why && <span>{step.why}</span>}
                </div>
                {step.command && (
                  <button
                    type="button"
                    className="enrich-copy"
                    onClick={() => copy(step.command || '', `cmd-${step.order}`)}
                    title="Copiar comando"
                  >
                    {copied === `cmd-${step.order}` ? <Check size={12} /> : <Copy size={12} />}
                    <code>{step.command}</code>
                  </button>
                )}
              </li>
            ))}
          </ol>
        </div>
      )}

      {!compact && (asset || network) && (
        <div className="enrich-grid">
          {asset && (
            <div className="enrich-block">
              <h5><Server size={13} /> Activo afectado</h5>
              <ul className="enrich-facts">
                <li><span>Equipo</span><strong>{asset.name} ({asset.agent_id})</strong></li>
                <li><span>Criticidad</span><strong>{CRITICALITY_LABEL[asset.criticality] || asset.criticality}</strong></li>
                {asset.os && <li><span>Sistema</span><strong>{asset.os}</strong></li>}
                {asset.owner && <li><span>Responsable</span><strong>{asset.owner}</strong></li>}
                {asset.location && <li><span>Ubicación</span><strong>{asset.location}</strong></li>}
              </ul>
            </div>
          )}
          {network && (
            <div className="enrich-block">
              <h5><Globe size={13} /> Contexto de red</h5>
              <ul className="enrich-facts">
                {network.service && <li><span>Servicio</span><strong>{network.service}</strong></li>}
                {network.direction && <li><span>Dirección</span><strong>{network.direction === 'inbound' ? 'Entrante' : network.direction === 'outbound' ? 'Saliente' : network.direction}</strong></li>}
                {network.src_ip && <li><span>Origen</span><strong>{network.src_ip}{network.src_port ? `:${network.src_port}` : ''}</strong></li>}
                {network.dst_ip && <li><span>Destino</span><strong>{network.dst_ip}{network.dst_port ? `:${network.dst_port}` : ''}</strong></li>}
                {network.country && <li><span>País</span><strong>{network.country}</strong></li>}
                {network.asn && <li><span>Red</span><strong>{network.asn}</strong></li>}
              </ul>
            </div>
          )}
        </div>
      )}

      {!compact && (tactics.length > 0 || techniques.length > 0) && (
        <div className="enrich-block">
          <h5><Crosshair size={13} /> MITRE ATT&CK</h5>
          <div className="enrich-chips">
            {tactics.map((t) => <span key={t} className="enrich-chip tactic">{t}</span>)}
            {techniques.map((t) => <span key={t} className="enrich-chip">{t}</span>)}
          </div>
        </div>
      )}

      {!compact && iocs.length > 0 && (
        <div className="enrich-block">
          <h5><ShieldAlert size={13} /> Indicadores (IoCs)</h5>
          <div className="enrich-chips">
            {iocs.slice(0, 12).map((ioc) => (
              <button
                key={`${ioc.type}-${ioc.value}`}
                type="button"
                className="enrich-chip ioc"
                onClick={() => copy(ioc.value, `ioc-${ioc.type}-${ioc.value}`)}
                title={`Copiar ${ioc.type}`}
              >
                <span>{ioc.type}</span>
                {ioc.defanged || ioc.value}
                {copied === `ioc-${ioc.type}-${ioc.value}` ? <Check size={11} /> : <Copy size={11} />}
              </button>
            ))}
          </div>
        </div>
      )}

      {!compact && (
        <div className="enrich-technical">
          <button type="button" className="enrich-toggle" onClick={() => setShowTechnical((v) => !v)}>
            <ChevronDown size={13} style={{ transform: showTechnical ? 'rotate(180deg)' : 'none' }} />
            {showTechnical ? 'Ocultar detalle técnico' : 'Ver detalle técnico'}
          </button>
          {showTechnical && (
            <div className="enrich-technical-body">
              {enrichment.translations.full_log_es && (
                <>
                  <h6>Log traducido</h6>
                  <pre>{enrichment.translations.full_log_es}</pre>
                </>
              )}
              {rawJson && (
                <>
                  <h6>Evento original</h6>
                  <pre>{rawJson}</pre>
                </>
              )}
              <div className="enrich-sources">
                Fuentes: {(enrichment.sources || []).join(', ') || 'interna'} · método: {enrichment.translations.method} · {(enrichment.elapsed_ms || 0).toFixed(1)} ms
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default EnrichmentPanel;
