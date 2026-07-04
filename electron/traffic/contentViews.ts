// Content view registry: detects and renders specialised content types.

export interface ContentView {
  id: string;
  name: string;
  priority?: number;
  detect(body: string, contentType: string, url?: string): boolean;
  render(body: string, contentType: string): string;
}

const VIEWS: ContentView[] = [];

export function registerView(view: ContentView): void {
  VIEWS.push(view);
}

export function detectView(body: string, contentType: string, url?: string): ContentView | null {
  const sorted = [...VIEWS].sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  return sorted.find((v) => v.detect(body, contentType, url)) ?? null;
}

export function renderBody(body: string, contentType: string, url?: string): { viewId: string; rendered: string } {
  const cap = body.slice(0, 2 * 1024 * 1024); // 2 MB cap
  const view = detectView(cap, contentType, url);
  if (view) {
    try {
      return { viewId: view.id, rendered: view.render(cap, contentType) };
    } catch {
      return { viewId: 'raw', rendered: cap };
    }
  }
  return { viewId: 'raw', rendered: cap };
}

export function getAllViews(): ContentView[] {
  return [...VIEWS];
}
