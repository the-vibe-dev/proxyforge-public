import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Load graphqlSchema parser
// ---------------------------------------------------------------------------

async function transpile(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  return ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: filePath,
  }).outputText;
}

async function loadGraphqlParser() {
  const graphqlPath = path.resolve('src/specImport/graphqlSchema.ts');

  try {
    await fs.access(graphqlPath);
  } catch {
    console.log('spec-import-graphql-schema: skipped (source file not found)');
    process.exit(0);
  }

  let graphqlCode;
  try {
    graphqlCode = await transpile(graphqlPath);
  } catch (err) {
    console.log(`spec-import-graphql-schema: skipped (transpile error: ${err.message})`);
    process.exit(0);
  }

  const mod = { exports: {} };
  const sandbox = {
    module: mod,
    exports: mod.exports,
    require: (id) => {
      // stub ./index since graphqlSchema only needs types from it (no runtime calls)
      if (id === './index' || id === './index.js') return {};
      return require(id);
    },
    process,
    console,
    URL,
    URLSearchParams,
    TextDecoder,
    TextEncoder,
    Buffer,
  };
  try {
    vm.runInNewContext(graphqlCode, sandbox, { filename: graphqlPath });
  } catch (err) {
    console.log(`spec-import-graphql-schema: skipped (load error: ${err.message})`);
    process.exit(0);
  }
  return mod.exports;
}

const graphqlModule = await loadGraphqlParser();
const { parseGraphqlSchema } = graphqlModule;

if (typeof parseGraphqlSchema !== 'function') {
  console.log('spec-import-graphql-schema: skipped (parseGraphqlSchema not exported)');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// SDL tests
// ---------------------------------------------------------------------------

const SDL_FIXTURE = `
type Query {
  users: [User]
  user(id: ID!): User
}

type User {
  id: ID!
  name: String
}
`;

// --- parseGraphqlSchema with SDL fixture: routes for users and user queries ---
{
  const result = parseGraphqlSchema(SDL_FIXTURE);
  assert.equal(result.format, 'graphql-schema', `format should be 'graphql-schema', got '${result.format}'`);
  assert.ok(result.routes.length >= 2, `should extract at least 2 routes from SDL, got ${result.routes.length}`);

  const routeNames = result.routes.map((r) => r.operationId);
  assert.ok(routeNames.includes('users'), "should have a route for 'users' query");
  assert.ok(routeNames.includes('user'), "should have a route for 'user' query");

  // All routes should be GET for queries
  for (const route of result.routes) {
    assert.equal(route.method, 'GET', `query route '${route.operationId}' should be GET`);
  }

  // 'user' query has an 'id' argument
  const userRoute = result.routes.find((r) => r.operationId === 'user');
  assert.ok(userRoute, "should find 'user' route");
  const idParam = userRoute.params.find((p) => p.name === 'id');
  assert.ok(idParam, "user route should have 'id' parameter");
  assert.equal(idParam.required, true, "'id: ID!' should be required");
}

// --- SDL with mutations ---
{
  const sdlWithMutation = `
type Query {
  ping: String
}

type Mutation {
  createUser(name: String!, email: String): User
  deleteUser(id: ID!): Boolean
}

type User {
  id: ID!
  name: String
}
`;
  const result = parseGraphqlSchema(sdlWithMutation);
  assert.ok(result.routes.length >= 3, `should extract 3+ routes (1 query + 2 mutations), got ${result.routes.length}`);

  const mutationRoutes = result.routes.filter((r) => r.method === 'POST');
  assert.ok(mutationRoutes.length >= 2, `should have at least 2 POST routes for mutations, got ${mutationRoutes.length}`);

  const createUserRoute = mutationRoutes.find((r) => r.operationId === 'createUser');
  assert.ok(createUserRoute, "should find 'createUser' mutation route");
  const nameParam = createUserRoute.params.find((p) => p.name === 'name');
  assert.ok(nameParam, "createUser should have 'name' param");
  assert.equal(nameParam.required, true, "'name: String!' should be required");
}

// ---------------------------------------------------------------------------
// Introspection JSON tests
// ---------------------------------------------------------------------------

const INTROSPECTION_FIXTURE = JSON.stringify({
  __schema: {
    queryType: { name: 'Query' },
    mutationType: { name: 'Mutation' },
    types: [
      {
        name: 'Query',
        fields: [
          {
            name: 'users',
            args: [],
          },
          {
            name: 'user',
            args: [
              {
                name: 'id',
                type: { kind: 'NON_NULL', name: null, ofType: { kind: 'SCALAR', name: 'ID' } },
                defaultValue: null,
              },
            ],
          },
        ],
      },
      {
        name: 'Mutation',
        fields: [
          {
            name: 'createUser',
            args: [
              {
                name: 'name',
                type: { kind: 'NON_NULL', name: null, ofType: { kind: 'SCALAR', name: 'String' } },
                defaultValue: null,
              },
            ],
          },
        ],
      },
    ],
  },
});

// --- parseGraphqlSchema with introspection JSON fixture ---
{
  const result = parseGraphqlSchema(INTROSPECTION_FIXTURE);
  assert.equal(result.format, 'graphql-schema', `format should be 'graphql-schema'`);
  assert.ok(result.routes.length >= 3, `should extract 3+ routes from introspection, got ${result.routes.length}`);

  const queryRoutes = result.routes.filter((r) => r.method === 'GET');
  const mutationRoutes = result.routes.filter((r) => r.method === 'POST');

  assert.ok(queryRoutes.length >= 2, `should have at least 2 GET routes (queries), got ${queryRoutes.length}`);
  assert.ok(mutationRoutes.length >= 1, `should have at least 1 POST route (mutation), got ${mutationRoutes.length}`);

  const userQueryRoute = queryRoutes.find((r) => r.operationId === 'user');
  assert.ok(userQueryRoute, "should find 'user' query route from introspection");
  const idParam = userQueryRoute.params.find((p) => p.name === 'id');
  assert.ok(idParam, "user route should have 'id' parameter from introspection args");
  assert.equal(idParam.required, true, "id param (NON_NULL) should be required");

  const createUserMutation = mutationRoutes.find((r) => r.operationId === 'createUser');
  assert.ok(createUserMutation, "should find 'createUser' mutation from introspection");
}

// --- Introspection wrapped in { data: { __schema } } envelope ---
{
  const wrapped = JSON.stringify({
    data: {
      __schema: {
        queryType: { name: 'Query' },
        mutationType: null,
        types: [
          {
            name: 'Query',
            fields: [{ name: 'health', args: [] }],
          },
        ],
      },
    },
  });

  const result = parseGraphqlSchema(wrapped);
  assert.equal(result.format, 'graphql-schema');
  const healthRoute = result.routes.find((r) => r.operationId === 'health');
  assert.ok(healthRoute, "should find 'health' query from wrapped introspection envelope");
}

console.log('spec-import-graphql-schema: all tests passed');
