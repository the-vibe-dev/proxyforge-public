// Disk-backed body spool for large captured bodies.
// Uses node:fs (sync) only — no external dependencies.

import * as fs from 'node:fs';
import * as path from 'node:path';

export interface SpoolEntry {
  id: string;
  path: string;
  size: number;
  capped: boolean;
  mimeType: string;
  createdAt: string;
}

const INDEX_FILE = 'spool-index.json';

/**
 * A simple disk-backed store that maps string IDs to body files.
 * Bodies are written as raw binary files; metadata is kept in a JSON index.
 */
export class SpoolStore {
  private readonly baseDir: string;
  private readonly indexPath: string;
  private index: Map<string, SpoolEntry>;

  constructor(baseDir: string) {
    this.baseDir = baseDir;
    this.indexPath = path.join(baseDir, INDEX_FILE);
    fs.mkdirSync(baseDir, { recursive: true });
    this.index = this._loadIndex();
  }

  private _loadIndex(): Map<string, SpoolEntry> {
    try {
      const raw = fs.readFileSync(this.indexPath, 'utf8');
      const entries = JSON.parse(raw) as SpoolEntry[];
      return new Map(entries.map((e) => [e.id, e]));
    } catch {
      return new Map();
    }
  }

  private _saveIndex(): void {
    const entries = Array.from(this.index.values());
    fs.writeFileSync(this.indexPath, JSON.stringify(entries, null, 2), 'utf8');
  }

  private _bodyPath(id: string): string {
    // Sanitise id to avoid path traversal
    const safe = id.replace(/[^a-zA-Z0-9_\-.]/g, '_');
    return path.join(this.baseDir, `${safe}.body`);
  }

  /**
   * Writes body data to disk and records the entry in the index.
   * If an entry with the same id already exists it is overwritten.
   */
  write(id: string, data: Buffer, mimeType: string, capped: boolean = false): SpoolEntry {
    const bodyPath = this._bodyPath(id);
    fs.writeFileSync(bodyPath, data);
    const entry: SpoolEntry = {
      id,
      path: bodyPath,
      size: data.length,
      capped,
      mimeType,
      createdAt: new Date().toISOString(),
    };
    this.index.set(id, entry);
    this._saveIndex();
    return entry;
  }

  /**
   * Reads a body by id.  Returns null when the entry or file does not exist.
   */
  read(id: string): Buffer | null {
    const entry = this.index.get(id);
    if (!entry) return null;
    try {
      return fs.readFileSync(entry.path);
    } catch {
      return null;
    }
  }

  /**
   * Removes a body file and its index entry.
   * Returns true when something was deleted, false when the id was not found.
   */
  remove(id: string): boolean {
    const entry = this.index.get(id);
    if (!entry) return false;
    try {
      fs.unlinkSync(entry.path);
    } catch {
      // file may already be gone — continue to clean up the index
    }
    this.index.delete(id);
    this._saveIndex();
    return true;
  }

  /**
   * Returns all index entries, sorted by createdAt ascending.
   */
  list(): SpoolEntry[] {
    return Array.from(this.index.values()).sort(
      (a, b) => a.createdAt.localeCompare(b.createdAt),
    );
  }

  /**
   * Returns the sum of all recorded body sizes.
   */
  totalSize(): number {
    let total = 0;
    for (const entry of this.index.values()) {
      total += entry.size;
    }
    return total;
  }

  /**
   * Removes the oldest entries (by createdAt) until the total spool size is
   * at or below maxTotalBytes.  Returns the number of bytes freed.
   */
  prune(maxTotalBytes: number): number {
    let freed = 0;
    const sorted = this.list(); // already sorted oldest-first

    for (const entry of sorted) {
      if (this.totalSize() <= maxTotalBytes) break;
      freed += entry.size;
      this.remove(entry.id);
    }

    return freed;
  }
}
