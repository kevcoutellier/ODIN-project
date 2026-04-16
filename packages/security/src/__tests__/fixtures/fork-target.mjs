/* Test fixture for ForkSandbox — plain ESM so child fork can import it. */

export async function echo(value) {
  return value;
}

export async function addOne(x) {
  return x + 1;
}

export async function slow(ms) {
  await new Promise((r) => setTimeout(r, ms));
  return 'done';
}

export async function boom() {
  throw new Error('deliberate failure');
}

export async function leakEnv() {
  return {
    hasDbUrl: typeof process.env.ODIN_SECRET_DB_URL === 'string',
    hasApiKey: typeof process.env.ODIN_SECRET_API_KEY === 'string',
  };
}
