// ---------------------------------------------------------------------------
// Spec Import Barrel
// Re-exports everything from all spec-import modules so consumers can import
// from a single entry point without knowing the internal file structure.
//
// Add new parsers here as they are implemented.
// ---------------------------------------------------------------------------

// Core router and shared types
export * from './index';

// Individual parsers — types and functions
export * from './openApi';
export * from './postman';
export * from './graphqlSchema';

// Insomnia v4 export parser
export * from './insomnia';

// SOAP/WSDL 1.1 parser
export * from './soapWsdl';

// OData $metadata parser
export * from './odata';

// HAR seed/import parser
export * from './harSeed';

// TODO: export * from './asyncApi';     // AsyncAPI 2/3 — not yet implemented
// TODO: export * from './raml';         // RAML 1.0 — not yet implemented
// TODO: export * from './apiBlueprint'; // API Blueprint — not yet implemented
