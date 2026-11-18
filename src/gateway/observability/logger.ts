import { redactSensitiveData } from '../config/security.ts';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface StructuredLogEntry {
  timestamp: string;
  level: LogLevel;
  event: string;
  message: string;
  gatewayId?: string;
  correlationId?: string;
  requestId?: string;
  agentId?: string;
  accountId?: string;
  mcpServerId?: string;
  sessionId?: string;
  toolName?: string;
  outcome?: 'success' | 'failure' | 'denied';
  details?: Record<string, unknown>;
}

export class GatewayLogger {
  private readonly gatewayId: string;
  private readonly silent: boolean;
  private readonly buffer: StructuredLogEntry[] = [];
  private readonly maxBufferSize: number;

  constructor(options: { gatewayId: string; silent?: boolean; maxBufferSize?: number }) {
    this.gatewayId = options.gatewayId;
    this.silent = options.silent ?? false;
    this.maxBufferSize = options.maxBufferSize ?? 250;
  }

  log(level: LogLevel, entry: Omit<StructuredLogEntry, 'timestamp' | 'level' | 'gatewayId'>): void {
    const safeDetails = entry.details
      ? (redactSensitiveData(entry.details) as Record<string, unknown>)
      : undefined;

    const record: StructuredLogEntry = {
      timestamp: new Date().toISOString(),
      level,
      gatewayId: this.gatewayId,
      ...entry,
      details: safeDetails,
    };

    this.buffer.unshift(record);
    if (this.buffer.length > this.maxBufferSize) {
      this.buffer.length = this.maxBufferSize;
    }

    if (!this.silent) {
      const line = JSON.stringify(record);
      if (level === 'error') {
        console.error(line);
      } else if (level === 'warn') {
        console.warn(line);
      } else {
        console.log(line);
      }
    }
  }

  info(entry: Omit<StructuredLogEntry, 'timestamp' | 'level' | 'gatewayId'>): void {
    this.log('info', entry);
  }

  warn(entry: Omit<StructuredLogEntry, 'timestamp' | 'level' | 'gatewayId'>): void {
    this.log('warn', entry);
  }

  error(entry: Omit<StructuredLogEntry, 'timestamp' | 'level' | 'gatewayId'>): void {
    this.log('error', entry);
  }

  getRecentEntries(limit = 100): StructuredLogEntry[] {
    return this.buffer.slice(0, Math.min(limit, this.buffer.length));
  }

  clear(): void {
    this.buffer.length = 0;
  }
}
