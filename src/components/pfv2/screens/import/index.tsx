// Import Wizard: pick a spec file, preview routes, confirm seeding.
import React, { useState, useCallback } from 'react';
import { importSpec, detectFormat, type SpecFormat, type SpecImportResult } from '../../../../specImport/index';

type WizardStep = 'pick' | 'preview' | 'confirm' | 'done';

interface ImportWizardProps {
  onSeed?: (result: SpecImportResult) => void;
  onClose?: () => void;
}

const FORMAT_LABELS: Record<string, string> = {
  openapi3: 'OpenAPI 3.x',
  swagger2: 'Swagger 2.0',
  postman: 'Postman Collection',
  insomnia: 'Insomnia Export',
  'soap-wsdl': 'SOAP/WSDL',
  'graphql-schema': 'GraphQL Schema',
  har: 'HAR Archive',
  odata: 'OData $metadata',
};

export function ImportWizard({ onSeed, onClose }: ImportWizardProps) {
  const [step, setStep] = useState<WizardStep>('pick');
  const [raw, setRaw] = useState('');
  const [detectedFormat, setDetectedFormat] = useState<SpecFormat | null>(null);
  const [result, setResult] = useState<SpecImportResult | null>(null);
  const [error, setError] = useState('');
  const [fileName, setFileName] = useState('');

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      setRaw(text);
      const fmt = detectFormat(text);
      setDetectedFormat(fmt);
      setError('');
    };
    reader.readAsText(file);
  }, []);

  const handlePreview = useCallback(() => {
    if (!raw) { setError('No file selected.'); return; }
    try {
      const parsed = importSpec(raw, detectedFormat ?? undefined);
      setResult(parsed);
      setStep('preview');
      setError('');
    } catch (e) {
      setError(`Parse error: ${e}`);
    }
  }, [raw, detectedFormat]);

  const handleConfirm = useCallback(() => {
    if (result) {
      onSeed?.(result);
      setStep('done');
    }
  }, [result, onSeed]);

  return (
    <div className="flex flex-col gap-4 p-4 bg-[#0f1117] text-gray-300 min-h-[400px]">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Import API Spec</h2>
        {onClose && (
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200 text-sm px-2 py-1 rounded hover:bg-[#1c1f2b]">
            ✕ Close
          </button>
        )}
      </div>

      {/* Step indicator */}
      <StepBar current={step} />

      {/* Step content */}
      {step === 'pick' && (
        <PickStep
          fileName={fileName}
          detectedFormat={detectedFormat}
          error={error}
          onFileChange={handleFileChange}
          onPreview={handlePreview}
        />
      )}
      {step === 'preview' && result && (
        <PreviewStep
          result={result}
          onBack={() => setStep('pick')}
          onConfirm={handleConfirm}
        />
      )}
      {step === 'confirm' && (
        <div className="text-gray-400 text-sm">Seeding project…</div>
      )}
      {step === 'done' && (
        <DoneStep result={result!} onClose={onClose} />
      )}
    </div>
  );
}

// ---- Sub-components ----

function StepBar({ current }: { current: WizardStep }) {
  const steps: WizardStep[] = ['pick', 'preview', 'confirm', 'done'];
  const labels: Record<WizardStep, string> = { pick: 'Select', preview: 'Preview', confirm: 'Confirm', done: 'Done' };
  const idx = steps.indexOf(current);
  return (
    <div className="flex gap-0">
      {steps.map((s, i) => (
        <div key={s} className="flex items-center">
          <div className={`flex items-center gap-1.5 px-3 py-1 text-xs rounded ${i === idx ? 'bg-indigo-600 text-white' : i < idx ? 'text-indigo-400' : 'text-gray-600'}`}>
            <span className={`w-4 h-4 flex items-center justify-center rounded-full text-[10px] font-bold ${i === idx ? 'bg-white text-indigo-600' : i < idx ? 'bg-indigo-900 text-indigo-300' : 'bg-[#1c1f2b] text-gray-600'}`}>{i + 1}</span>
            {labels[s]}
          </div>
          {i < steps.length - 1 && <div className="w-4 h-px bg-[#2a2d3a] mx-0.5" />}
        </div>
      ))}
    </div>
  );
}

function PickStep({ fileName, detectedFormat, error, onFileChange, onPreview }: {
  fileName: string;
  detectedFormat: SpecFormat | null;
  error: string;
  onFileChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onPreview: () => void;
}) {
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-gray-400">
        Import an API spec to seed your Target Map, insertion-point inventory, and Repeater tabs.
        Supported formats: OpenAPI 3, Swagger 2, Postman, Insomnia, SOAP/WSDL, GraphQL SDL, HAR, OData.
      </p>
      <label className="flex flex-col gap-2">
        <span className="text-xs text-gray-500 uppercase tracking-wide">Select file</span>
        <div className="flex items-center gap-3 border border-[#2a2d3a] rounded-lg px-4 py-3 bg-[#13151f] cursor-pointer hover:border-indigo-500 transition-colors">
          <span className="text-gray-400 text-sm">{fileName || 'No file chosen'}</span>
          <input type="file" accept=".json,.yaml,.yml,.xml,.wsdl,.graphql,.gql,.har" onChange={onFileChange} className="sr-only" />
          <span className="ml-auto text-xs bg-[#1c1f2b] text-gray-300 px-3 py-1.5 rounded hover:bg-[#252839]">Browse…</span>
        </div>
      </label>
      {detectedFormat && (
        <div className="flex items-center gap-2 text-sm">
          <span className="text-gray-500">Detected format:</span>
          <span className="px-2 py-0.5 bg-indigo-900/40 text-indigo-300 rounded text-xs font-mono">
            {FORMAT_LABELS[detectedFormat] ?? detectedFormat}
          </span>
        </div>
      )}
      {error && <p className="text-red-400 text-xs">{error}</p>}
      <button
        onClick={onPreview}
        disabled={!fileName}
        className="mt-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm rounded-lg transition-colors w-fit"
      >
        Preview →
      </button>
    </div>
  );
}

function PreviewStep({ result, onBack, onConfirm }: {
  result: SpecImportResult;
  onBack: () => void;
  onConfirm: () => void;
}) {
  const methodColor: Record<string, string> = {
    GET: 'text-green-400', POST: 'text-yellow-400', PUT: 'text-blue-400',
    PATCH: 'text-orange-400', DELETE: 'text-red-400', HEAD: 'text-gray-400', OPTIONS: 'text-purple-400',
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-4 text-sm">
        {result.title && <span className="text-white font-medium">{result.title}</span>}
        {result.version && <span className="text-gray-500">v{result.version}</span>}
        {result.baseUrl && <span className="text-gray-500 font-mono text-xs">{result.baseUrl}</span>}
        <span className="ml-auto text-indigo-400 font-medium">{result.routes.length} routes</span>
      </div>

      {result.errors && result.errors.length > 0 && (
        <div className="border border-red-900/50 bg-red-900/10 rounded p-3 text-xs text-red-300">
          {result.errors.map((e, i) => <div key={i}>{e}</div>)}
        </div>
      )}

      <div className="border border-[#1e2130] rounded-lg overflow-hidden">
        <div className="max-h-64 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="bg-[#13151f] sticky top-0">
              <tr>
                <th className="px-3 py-2 text-left text-gray-500 font-medium w-16">Method</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">Path</th>
                <th className="px-3 py-2 text-right text-gray-500 font-medium w-16">Params</th>
              </tr>
            </thead>
            <tbody>
              {result.routes.slice(0, 200).map((route, i) => (
                <tr key={i} className="border-t border-[#1a1d28] hover:bg-[#13151f]">
                  <td className={`px-3 py-1.5 font-mono font-bold ${methodColor[route.method] ?? 'text-gray-400'}`}>
                    {route.method}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-gray-300 truncate max-w-xs">{route.path}</td>
                  <td className="px-3 py-1.5 text-right text-gray-500">{route.params.length}</td>
                </tr>
              ))}
              {result.routes.length > 200 && (
                <tr className="border-t border-[#1a1d28]">
                  <td colSpan={3} className="px-3 py-2 text-center text-gray-600 text-xs">
                    …and {result.routes.length - 200} more routes
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="flex gap-3">
        <button onClick={onBack} className="px-4 py-2 border border-[#2a2d3a] text-gray-400 hover:text-white hover:border-gray-500 text-sm rounded-lg transition-colors">
          ← Back
        </button>
        <button onClick={onConfirm} disabled={result.routes.length === 0} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm rounded-lg transition-colors">
          Seed Project ({result.routes.length} routes)
        </button>
      </div>
    </div>
  );
}

function DoneStep({ result, onClose }: { result: SpecImportResult; onClose?: () => void }) {
  return (
    <div className="flex flex-col items-center gap-4 py-8">
      <div className="w-12 h-12 rounded-full bg-green-900/30 flex items-center justify-center text-green-400 text-2xl">✓</div>
      <p className="text-white font-medium">Import complete</p>
      <p className="text-gray-400 text-sm text-center">
        {result.routes.length} routes seeded into your Target Map and insertion-point inventory.
      </p>
      {onClose && (
        <button onClick={onClose} className="px-4 py-2 bg-[#1c1f2b] hover:bg-[#252839] text-gray-300 text-sm rounded-lg transition-colors">
          Close
        </button>
      )}
    </div>
  );
}
