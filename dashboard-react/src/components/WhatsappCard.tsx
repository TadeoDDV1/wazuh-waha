import React, { useEffect, useState, useCallback, useRef } from 'react';
import './ComponentCard.css';
import './WhatsappCard.css';
import type { Component } from '../types/dashboard';
import { dashboardService } from '../services/api';
import { toast } from 'sonner';
import {
  QrCode,
  Play,
  Square,
  LogOut,
  PlusCircle,
  RefreshCw,
  CheckCircle2,
  X,
  Smartphone,
  Loader2,
} from 'lucide-react';
import { CATEGORY_LABELS } from '../utils/constants';

const QR_REFRESH_MS = 20_000; // el QR rota aprox. cada 20s

export const WhatsappCard: React.FC<{ component: Component }> = ({ component }) => {
  const [qrUrl, setQrUrl] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showQrModal, setShowQrModal] = useState(false);
  const [modalQrUrl, setModalQrUrl] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [checkSessionInterval, setCheckSessionInterval] = useState<ReturnType<typeof setInterval> | null>(null);
  const qrUrlRef = useRef<string | null>(null);

  const health = component.health || 'unknown';
  const detail = component.detail || '';

  const isScanQr = detail.includes('SCAN_QR') || detail.includes('SCANNING_QR');
  const isMissing = detail.includes('missing');
  const isWorking = health === 'healthy' && detail.includes('WORKING');

  const fetchQr = useCallback(async () => {
    try {
      const blob = await dashboardService.getQrBlob();
      if (!blob) return;
      const url = URL.createObjectURL(blob);
      if (qrUrlRef.current) URL.revokeObjectURL(qrUrlRef.current);
      qrUrlRef.current = url;
      setQrUrl(url);
    } catch {
      setQrUrl(null);
      if (qrUrlRef.current) {
        URL.revokeObjectURL(qrUrlRef.current);
        qrUrlRef.current = null;
      }
    }
  }, []);

  // Auto-refresh del QR mientras la sesión espera escaneo
  useEffect(() => {
    if (!isScanQr) return;
    fetchQr();
    const t = setInterval(fetchQr, QR_REFRESH_MS);
    return () => clearInterval(t);
  }, [isScanQr, fetchQr]);

  // Liberar object URL al desmontar
  useEffect(() => {
    return () => {
      if (qrUrlRef.current) URL.revokeObjectURL(qrUrlRef.current);
      if (modalQrUrl) URL.revokeObjectURL(modalQrUrl);
      if (checkSessionInterval) clearInterval(checkSessionInterval);
    };
  }, []);

  const runAction = async (action: 'create' | 'start' | 'stop' | 'logout') => {
    if (action === 'create' && isMissing) {
      setIsCreating(true);
      setBusy(true);
      try {
        const result = await dashboardService.wahaSessionAction(action);
        if (result.ok) {
          const blob = await dashboardService.getQrBlob();
          if (blob) {
            const url = URL.createObjectURL(blob);
            setModalQrUrl(url);
            setShowQrModal(true);

            const interval = setInterval(async () => {
              try {
                const statusResult = await dashboardService.getStatus();
                const wahaComponent = statusResult.components.find((c: any) => c.id === 'waha_session');
                if (wahaComponent && wahaComponent.health === 'healthy') {
                  clearInterval(interval);
                  setCheckSessionInterval(null);
                  setShowQrModal(false);
                  if (modalQrUrl) {
                    URL.revokeObjectURL(modalQrUrl);
                    setModalQrUrl(null);
                  }
                  toast.success('Sesión de WhatsApp vinculada exitosamente');
                }
              } catch (err) {
                console.error('Error checking session status:', err);
              }
            }, 3000);

            setCheckSessionInterval(interval);
          } else {
            toast.success('Sesión de WhatsApp creada/iniciada');
          }
        } else {
          toast.error(`Sesión: ${result.result}`);
        }
      } catch {
        toast.error('Falló la acción de crear sesión');
      } finally {
        setBusy(false);
        setIsCreating(false);
      }
    } else {
      setBusy(true);
      try {
        const result = await dashboardService.wahaSessionAction(action);
        if (result.ok) {
          toast.success(`Sesión: ${result.result}`);
        } else {
          toast.error(`Sesión: ${result.result}`);
        }
      } catch {
        toast.error(`Falló la acción '${action}'`);
      } finally {
        setBusy(false);
      }
    }
  };

  const handleCloseModal = () => {
    setShowQrModal(false);
    if (modalQrUrl) {
      URL.revokeObjectURL(modalQrUrl);
      setModalQrUrl(null);
    }
    if (checkSessionInterval) {
      clearInterval(checkSessionInterval);
      setCheckSessionInterval(null);
    }
  };

  return (
    <>
      <div className={`component-card whatsapp-card status-${health}`}>
        {/* Header */}
        <div className="card-header">
          <div className="card-title-group">
            <div className="card-icon-wrapper">
              <Smartphone size={20} style={{ color: 'var(--cyan-accent)' }} />
            </div>
            <div className="card-name-block">
              <h3 className="card-name">{component.name}</h3>
              <span className="card-category-tag">
                {CATEGORY_LABELS[component.category] || component.category}
              </span>
            </div>
          </div>

          {/* Status Badge */}
          <div className={`status-badge-chip ${health}`}>
            <span className="status-dot" />
            <span>{health}</span>
          </div>
        </div>

        {/* Body */}
        <div className="card-body">
          <p className="card-description">{component.description}</p>
          {detail && (
            <div className="card-detail-pill" title={detail}>
              <span>{detail}</span>
            </div>
          )}

          {isMissing && (
            <div className="qr-placeholder">
              <p>La sesión no existe aún en WAHA. Creala para vincular el teléfono.</p>
            </div>
          )}

          {isScanQr && qrUrl && (
            <div className="qr-area">
              <img src={qrUrl} alt="QR de vinculación de WhatsApp" className="qr-image" />
              <p className="qr-hint">
                Escaneá con WhatsApp → Dispositivos vinculados → Vincular dispositivo.
                El código rota cada ~20s.
              </p>
            </div>
          )}

          {isScanQr && !qrUrl && (
            <div className="qr-placeholder">
              <Loader2 size={16} className="animate-spin" style={{ marginRight: '0.5rem' }} />
              Cargando código QR...
            </div>
          )}

          {/* Active session banner */}
          {isWorking && (
            <div className="session-active-banner">
              <CheckCircle2 size={16} />
              <span>SESIÓN VINCULADA Y ACTIVA · Lista para notificaciones</span>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="card-footer">
          <div className="card-actions" style={{ width: '100%', justifyContent: 'flex-end' }}>
            {isMissing && (
              <button
                className="card-action-btn"
                disabled={busy}
                onClick={() => runAction('create')}
              >
                {isCreating ? <Loader2 size={13} className="animate-spin" /> : <PlusCircle size={13} />}
                <span>{isCreating ? 'Creando...' : 'Crear Sesión'}</span>
              </button>
            )}

            {(isScanQr || detail === 'STOPPED' || detail === 'STARTING') && (
              <button
                className="card-action-btn"
                disabled={busy}
                onClick={() => runAction('start')}
              >
                <Play size={13} />
                <span>Iniciar Sesión</span>
              </button>
            )}

            {isScanQr && (
              <button
                className="card-action-btn"
                disabled={busy}
                onClick={fetchQr}
                title="Generar o refrescar código QR"
              >
                <RefreshCw size={13} className={busy ? 'animate-spin' : ''} />
                <span>Refrescar QR</span>
              </button>
            )}

            {isWorking && (
              <>
                <button
                  className="card-action-btn"
                  disabled={busy}
                  onClick={() => runAction('stop')}
                  title="Detener sesión temporalmente"
                >
                  <Square size={13} />
                  <span>Detener</span>
                </button>
                <button
                  className="card-action-btn"
                  disabled={busy}
                  onClick={() => runAction('logout')}
                  title="Desvincular WhatsApp"
                >
                  <LogOut size={13} />
                  <span>Desvincular</span>
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      {/* QR Modal */}
      {showQrModal && (
        <div className="qr-modal-overlay" onClick={handleCloseModal}>
          <div className="qr-modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="qr-modal-header">
              <h3>
                <QrCode size={18} style={{ color: 'var(--cyan-accent)' }} />
                <span>Vincular WhatsApp</span>
              </h3>
              <button className="qr-modal-close" onClick={handleCloseModal}>
                <X size={16} />
              </button>
            </div>
            <div className="qr-modal-body">
              {modalQrUrl ? (
                <>
                  <div className="qr-modal-image-wrapper">
                    <img src={modalQrUrl} alt="QR para vincular WhatsApp" className="qr-modal-image" />
                  </div>
                  <p className="qr-modal-instructions">
                    Escanea este código con tu teléfono:
                    <br />
                    <strong>WhatsApp → Ajustes → Dispositivos vinculados → Vincular dispositivo</strong>
                  </p>
                  <p className="qr-modal-note">
                    El código se actualiza automáticamente por seguridad.
                  </p>
                </>
              ) : (
                <div className="qr-placeholder">
                  <Loader2 size={20} className="animate-spin" />
                  <p style={{ marginTop: '0.5rem' }}>Generando código QR...</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default WhatsappCard;

