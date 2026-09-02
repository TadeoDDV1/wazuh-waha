export const CATEGORY_ORDER = [
  'sec_ops',
  'integrity',
  'threat_detection',
  'auditing_policy',
  'whatsapp_gateway',
  'watchdogs',
  'notifications',
  'compliance',
] as const;

export const CATEGORY_LABELS: Record<string, string> = {
  sec_ops: 'Security Operations & SIEM',
  integrity: 'Integrity Monitoring (FIM)',
  threat_detection: 'Threat Detection & Vulnerabilities',
  auditing_policy: 'Auditing & Policy Monitoring',
  whatsapp_gateway: 'WhatsApp Gateway & Relay',
  watchdogs: 'Proactive Watchdogs & Health',
  notifications: 'Backup Channels & AI',
  compliance: 'Regulatory Compliance & Standards',
};

export const CATEGORY_ICONS: Record<string, string> = {
  sec_ops: 'ShieldAlert',
  integrity: 'FileCheck2',
  threat_detection: 'Bug',
  auditing_policy: 'ClipboardList',
  whatsapp_gateway: 'MessageSquare',
  watchdogs: 'Activity',
  notifications: 'BellRing',
  compliance: 'Landmark',
};

export const CATEGORY_DESCRIPTIONS: Record<string, string> = {
  sec_ops: 'Análisis de autenticación SSH, su, sudo, logins y respuesta activa',
  integrity: 'Monitoreo de integridad de archivos críticos y binarios con privilegios SUID',
  threat_detection: 'Detección de vulnerabilidades CVEs, malware de red y descargas sospechosas',
  auditing_policy: 'Auditoría CIS (SCA), detección de rootkits y telemetría de inventario',
  whatsapp_gateway: 'Gateway WAHA para despacho de alertas a WhatsApp y daemon de integración',
  watchdogs: 'Timers de auto-recuperación, detección de drift de IP y monitor de salud',
  notifications: 'Canales de respaldo por email (SMTP / Hyvor Relay) y modelos de IA local',
  compliance: 'Filtros para normativas PCI DSS, GDPR, HIPAA, NIST, TSC',
};

