// Frame-level editor for HTTP/2 Repeater — parse, display, edit, rebuild.

import type { Http2Frame } from './http2Transport';

export interface Http2EditableFrame {
  streamId: number;
  type: string;
  flags: number;
  payloadHex: string;
  pseudoHeaders?: Record<string, string>;
  headers?: Record<string, string>;
  data?: string;
}

/**
 * Converts an array of raw Http2Frame objects into editable display form.
 * HEADERS frames have their pseudo-headers and regular headers decoded from
 * the payload hex; DATA frames expose their body as a UTF-8 string where
 * possible (falling back to hex for binary content).
 */
export function parseFramesForDisplay(frames: Http2Frame[]): Http2EditableFrame[] {
  return frames.map((frame): Http2EditableFrame => {
    const base: Http2EditableFrame = {
      streamId: frame.streamId,
      type: frame.type,
      flags: frame.flags,
      payloadHex: frame.payload.toString('hex'),
    };

    if (frame.type === 'HEADERS') {
      // Attempt to decode payload as a newline-delimited header block
      // (simplified: real HPACK decompression not performed here — callers
      // supply pre-decoded header bytes for the editor layer).
      try {
        const text = frame.payload.toString('utf8');
        const pseudoHeaders: Record<string, string> = {};
        const headers: Record<string, string> = {};
        for (const line of text.split('\n')) {
          let key: string;
          let value: string;
          if (line.startsWith(':')) {
            const secondColon = line.indexOf(':', 1);
            if (secondColon === -1) continue;
            key = line.slice(0, secondColon).trim();
            value = line.slice(secondColon + 1).trim();
          } else {
            const colon = line.indexOf(':');
            if (colon === -1) continue;
            key = line.slice(0, colon).trim();
            value = line.slice(colon + 1).trim();
          }
          if (key.startsWith(':')) {
            pseudoHeaders[key] = value;
          } else if (key.length > 0) {
            headers[key] = value;
          }
        }
        base.pseudoHeaders = pseudoHeaders;
        base.headers = headers;
      } catch {
        // non-UTF8 payload; leave only payloadHex
      }
    } else if (frame.type === 'DATA') {
      try {
        base.data = frame.payload.toString('utf8');
      } catch {
        base.data = frame.payload.toString('hex');
      }
    }

    return base;
  });
}

/**
 * Converts an editable display frame back into a raw Http2Frame.
 * When pseudoHeaders/headers are present they are serialised into the payload;
 * when data is present it is encoded as UTF-8; otherwise payloadHex is used.
 */
export function buildFrameFromEdit(edit: Http2EditableFrame): Http2Frame {
  let payload: Buffer;

  if (edit.type === 'HEADERS' && (edit.pseudoHeaders || edit.headers)) {
    const lines: string[] = [];
    for (const [key, value] of Object.entries(edit.pseudoHeaders ?? {})) {
      lines.push(`${key}: ${value}`);
    }
    for (const [key, value] of Object.entries(edit.headers ?? {})) {
      lines.push(`${key}: ${value}`);
    }
    payload = Buffer.from(lines.join('\n'), 'utf8');
  } else if (edit.type === 'DATA' && edit.data !== undefined) {
    payload = Buffer.from(edit.data, 'utf8');
  } else {
    payload = Buffer.from(edit.payloadHex, 'hex');
  }

  return {
    streamId: edit.streamId,
    type: edit.type as Http2Frame['type'],
    flags: edit.flags,
    payload,
  };
}

/**
 * Serialises editable frames to a human-readable multi-line text format.
 *
 * Example output:
 *   HEADERS stream=1 flags=0x04
 *   :method: POST
 *   :path: /api/v1/users
 *   content-type: application/json
 *
 *   DATA stream=1 flags=0x01
 *   {"user":"alice"}
 */
export function serializeFramesToText(frames: Http2EditableFrame[]): string {
  const parts: string[] = [];

  for (const frame of frames) {
    const flagHex = `0x${frame.flags.toString(16).padStart(2, '0')}`;
    const heading = `${frame.type} stream=${frame.streamId} flags=${flagHex}`;
    const lines: string[] = [heading];

    if (frame.type === 'HEADERS') {
      for (const [key, value] of Object.entries(frame.pseudoHeaders ?? {})) {
        lines.push(`${key}: ${value}`);
      }
      for (const [key, value] of Object.entries(frame.headers ?? {})) {
        lines.push(`${key}: ${value}`);
      }
    } else if (frame.type === 'DATA' && frame.data !== undefined) {
      lines.push(frame.data);
    } else {
      if (frame.payloadHex.length > 0) {
        lines.push(frame.payloadHex);
      }
    }

    parts.push(lines.join('\n'));
  }

  return parts.join('\n\n');
}

/**
 * Parses the human-readable text format produced by serializeFramesToText
 * back into an array of Http2EditableFrame objects.
 */
export function parseFramesFromText(text: string): Http2EditableFrame[] {
  const blocks = text.split(/\n\n+/);
  const frames: Http2EditableFrame[] = [];

  for (const block of blocks) {
    const trimmed = block.trim();
    if (!trimmed) continue;

    const lines = trimmed.split('\n');
    const heading = lines[0].trim();

    // Parse heading: TYPE stream=N flags=0xHH
    const headingMatch = heading.match(
      /^(\S+)\s+stream=(\d+)(?:\s+flags=(0x[0-9a-fA-F]+|\d+))?/,
    );
    if (!headingMatch) continue;

    const type = headingMatch[1];
    const streamId = parseInt(headingMatch[2], 10);
    const flagsRaw = headingMatch[3] ?? '0x00';
    const flags = flagsRaw.startsWith('0x')
      ? parseInt(flagsRaw.slice(2), 16)
      : parseInt(flagsRaw, 10);

    const bodyLines = lines.slice(1);

    const frame: Http2EditableFrame = {
      streamId,
      type,
      flags,
      payloadHex: '',
    };

    if (type === 'HEADERS') {
      const pseudoHeaders: Record<string, string> = {};
      const headers: Record<string, string> = {};
      for (const line of bodyLines) {
        // Pseudo-headers look like ":method: GET" — they start with a colon,
        // so we must find the SECOND colon to split key from value.
        let key: string;
        let value: string;
        if (line.startsWith(':')) {
          const secondColon = line.indexOf(':', 1);
          if (secondColon === -1) continue;
          key = line.slice(0, secondColon).trim();
          value = line.slice(secondColon + 1).trim();
        } else {
          const colon = line.indexOf(':');
          if (colon === -1) continue;
          key = line.slice(0, colon).trim();
          value = line.slice(colon + 1).trim();
        }
        if (key.startsWith(':')) {
          pseudoHeaders[key] = value;
        } else if (key.length > 0) {
          headers[key] = value;
        }
      }
      frame.pseudoHeaders = pseudoHeaders;
      frame.headers = headers;
      // Build payloadHex from decoded headers for symmetry
      const headerLines = [
        ...Object.entries(pseudoHeaders).map(([k, v]) => `${k}: ${v}`),
        ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
      ];
      frame.payloadHex = Buffer.from(headerLines.join('\n'), 'utf8').toString('hex');
    } else if (type === 'DATA') {
      const dataBody = bodyLines.join('\n');
      frame.data = dataBody;
      frame.payloadHex = Buffer.from(dataBody, 'utf8').toString('hex');
    } else {
      // For other frame types assume payloadHex on the first body line
      const candidate = bodyLines[0]?.trim() ?? '';
      if (/^[0-9a-fA-F]*$/.test(candidate)) {
        frame.payloadHex = candidate;
      }
    }

    frames.push(frame);
  }

  return frames;
}
