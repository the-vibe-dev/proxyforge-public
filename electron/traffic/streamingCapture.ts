// SSE + large-body streaming capture with byte caps and duration limits.

export interface StreamCaptureConfig {
  maxBodyBytes: number;
  maxDurationMs: number;
  chunkCallback?: (chunk: Buffer, totalBytes: number) => void;
}

/**
 * Accumulates streaming chunks up to a configurable byte cap and/or
 * duration limit.  Callers call write() for each chunk, end() when the
 * stream closes, and then query getBytes() / isCapped() / isComplete().
 */
export class StreamCapture {
  private readonly config: StreamCaptureConfig;
  private readonly chunks: Buffer[] = [];
  private bytesReceived: number = 0;
  private capped: boolean = false;
  private complete: boolean = false;
  private readonly startedAt: number = Date.now();

  constructor(config: StreamCaptureConfig) {
    this.config = config;
  }

  /**
   * Appends a chunk to the accumulator.
   * Returns false when the cap has already been reached (chunk is still
   * partially accepted up to the remaining budget).
   */
  write(chunk: Buffer): boolean {
    if (this.capped) return false;

    const elapsed = Date.now() - this.startedAt;
    if (elapsed >= this.config.maxDurationMs) {
      this.capped = true;
      return false;
    }

    const remaining = this.config.maxBodyBytes - this.bytesReceived;
    if (chunk.length <= remaining) {
      this.chunks.push(chunk);
      this.bytesReceived += chunk.length;
    } else {
      // Partial accept
      const slice = chunk.subarray(0, remaining);
      this.chunks.push(slice);
      this.bytesReceived += slice.length;
      this.capped = true;
    }

    if (this.config.chunkCallback) {
      this.config.chunkCallback(chunk, this.bytesReceived);
    }

    if (this.bytesReceived >= this.config.maxBodyBytes) {
      this.capped = true;
      return false;
    }

    return true;
  }

  end(): void {
    this.complete = true;
  }

  getBytes(): Buffer {
    return Buffer.concat(this.chunks);
  }

  getBytesReceived(): number {
    return this.bytesReceived;
  }

  isCapped(): boolean {
    return this.capped;
  }

  isComplete(): boolean {
    return this.complete;
  }
}

/**
 * Truncates a body Buffer to maxBytes.  Returns the (possibly truncated)
 * body, a flag indicating whether truncation occurred, and the original size.
 */
export function capBodySize(
  body: Buffer,
  maxBytes: number,
): { body: Buffer; capped: boolean; originalSize: number } {
  const originalSize = body.length;
  if (body.length <= maxBytes) {
    return { body, capped: false, originalSize };
  }
  return { body: body.subarray(0, maxBytes), capped: true, originalSize };
}

/**
 * Returns true when the content-type indicates a streaming response that
 * should be handled incrementally (SSE, NDJSON, long-poll plain text).
 */
export function detectIsStreamingContentType(contentType: string): boolean {
  const lower = contentType.toLowerCase();
  if (lower.includes('text/event-stream')) return true;
  if (lower.includes('application/x-ndjson')) return true;
  // Long-poll: text/plain with charset=utf-8
  if (lower.includes('text/plain') && lower.includes('charset=utf-8')) return true;
  return false;
}

export interface SseEvent {
  event?: string;
  data: string;
  id?: string;
  retry?: number;
}

/**
 * Parses raw SSE stream text into discrete events.
 * Handles the full SSE field grammar: data, event, id, retry.
 * Multiple consecutive data lines are joined with newline per spec.
 */
export function parseSSEChunks(raw: string): SseEvent[] {
  const events: SseEvent[] = [];

  // Events are separated by blank lines
  const blocks = raw.split(/\r?\n\r?\n/);

  for (const block of blocks) {
    const trimmed = block.trim();
    if (!trimmed) continue;

    let event: string | undefined;
    let id: string | undefined;
    let retry: number | undefined;
    const dataLines: string[] = [];

    for (const line of trimmed.split(/\r?\n/)) {
      if (line.startsWith(':')) continue; // comment

      const colonIdx = line.indexOf(':');
      let field: string;
      let value: string;

      if (colonIdx === -1) {
        field = line;
        value = '';
      } else {
        field = line.slice(0, colonIdx);
        // Strip exactly one leading space from value per SSE spec
        value = line.slice(colonIdx + 1).replace(/^ /, '');
      }

      switch (field) {
        case 'data':
          dataLines.push(value);
          break;
        case 'event':
          event = value;
          break;
        case 'id':
          id = value;
          break;
        case 'retry': {
          const n = parseInt(value, 10);
          if (!isNaN(n)) retry = n;
          break;
        }
      }
    }

    if (dataLines.length === 0) continue; // no data field → ignore per spec

    const sseEvent: SseEvent = { data: dataLines.join('\n') };
    if (event !== undefined) sseEvent.event = event;
    if (id !== undefined) sseEvent.id = id;
    if (retry !== undefined) sseEvent.retry = retry;
    events.push(sseEvent);
  }

  return events;
}
