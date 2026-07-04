// Multi-language API client stub generator registry.
// Generates typed client bindings from the ProxyForge JSON-RPC schema contract.
// No external dependencies.

export type GeneratorLanguage = 'python' | 'nodejs' | 'java' | 'rust' | 'go' | 'php' | 'wiki';

export interface GeneratorInput {
  language: GeneratorLanguage;
  baseUrl?: string;
  namespace?: string;
  outputDir?: string;
}

export interface GeneratorOutput {
  language: GeneratorLanguage;
  files: Array<{ filename: string; content: string }>;
  warnings?: string[];
}

export interface OpSchema {
  op: string;
  description: string;
  required: string[];
  optional?: string[];
}

// Minimal op schema derived from agentProtocol.ts
export const OP_SCHEMAS: OpSchema[] = [
  { op: 'project.create', description: 'Create a new project', required: ['name'] },
  { op: 'project.open', description: 'Open an existing project', required: ['path'] },
  { op: 'proxy.start', description: 'Start the proxy listener', required: ['projectId', 'listen'] },
  { op: 'proxy.stop', description: 'Stop the proxy listener', required: ['projectId'] },
  { op: 'browser.launch', description: 'Launch a managed browser', required: ['projectId'] },
  { op: 'history.query', description: 'Query captured exchange history', required: ['projectId'], optional: ['filter'] },
  { op: 'repeater.send', description: 'Send a request from Repeater', required: ['projectId', 'request'] },
  { op: 'scanner.run', description: 'Run a scanner check against an exchange', required: ['projectId', 'exchangeId'], optional: ['checks'] },
  { op: 'scanner.matrix.fetch', description: 'Fetch a probe matrix by ID', required: ['projectId', 'matrixId'] },
  { op: 'oast.payload.create', description: 'Create an OAST payload token', required: ['projectId', 'purpose'] },
  { op: 'oast.interactions.poll', description: 'Poll for OAST callback interactions', required: ['projectId'] },
  { op: 'exploit.template.run', description: 'Run an exploit template', required: ['projectId', 'templateId', 'input'] },
  { op: 'playbook.run', description: 'Run an automation recipe', required: ['projectId', 'recipeId'] },
  { op: 'issue.promote', description: 'Promote evidence to an issue', required: ['projectId', 'evidenceIds'] },
  { op: 'report.export', description: 'Export a project report', required: ['projectId', 'format'] },
  { op: 'extension.invoke', description: 'Invoke an extension hook', required: ['projectId', 'extensionId', 'hook'] },
];

export function generate(input: GeneratorInput): GeneratorOutput {
  switch (input.language) {
    case 'python': return { language: 'python', files: generatePython(input) };
    case 'nodejs': return { language: 'nodejs', files: generateNodeJs(input) };
    case 'java': return { language: 'java', files: generateJava(input) };
    case 'rust': return { language: 'rust', files: generateRust(input) };
    case 'go': return { language: 'go', files: generateGo(input) };
    case 'php': return { language: 'php', files: generatePhp(input) };
    case 'wiki': return { language: 'wiki', files: generateWiki(input) };
    default: return { language: input.language, files: [], warnings: ['Unknown language'] };
  }
}

import { generatePython } from './pythonGenerator';
import { generateNodeJs } from './nodeJsGenerator';
import { generateJava } from './javaGenerator';
import { generateRust } from './rustGenerator';
import { generateGo } from './goGenerator';
import { generatePhp } from './phpGenerator';
import { generateWiki } from './wikiGenerator';
