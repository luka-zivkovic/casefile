#!/usr/bin/env node
import { runCasefileBenchmarkAdapter } from './trust-benchmark-adapter.js';
import { decodeTrustBenchmarkAdapterRequest, TrustBenchmarkProtocolError } from './trust-benchmark-protocol.js';

const MAX_REQUEST_BYTES = 1024 * 1024;

async function readStdin(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > MAX_REQUEST_BYTES) {
      throw new TrustBenchmarkProtocolError(`request exceeds ${MAX_REQUEST_BYTES} bytes`);
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, length);
}

async function main(): Promise<void> {
  try {
    const request = decodeTrustBenchmarkAdapterRequest(await readStdin());
    const result = runCasefileBenchmarkAdapter(request);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (cause) {
    const message = cause instanceof TrustBenchmarkProtocolError ? cause.message : 'unexpected adapter failure';
    process.stderr.write(`casefile benchmark adapter: invalid request: ${message}\n`);
    process.exitCode = 2;
  }
}

void main();
