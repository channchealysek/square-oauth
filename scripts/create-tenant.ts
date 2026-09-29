import { loadMongoUri } from '../src/config.js';
import { generateTenantSecret, hashTenantSecret } from '../src/crypto/secrets.js';
import { DuplicateTenantError } from '../src/domain/errors.js';
import { isTenantId, normalizeBaseUrl } from '../src/domain/urls.js';
import { connectMongo, disconnectMongo } from '../src/repositories/models.js';
import { MongoTenantRepository } from '../src/repositories/mongo.js';

async function main(): Promise<void> {
  const tenantId = argument('id');
  const baseUrlInput = argument('url');
  if (!tenantId || !baseUrlInput) {
    throw new Error('Usage: npm run tenant:create -- --id <tenant-id> --url <https-base-url>');
  }
  if (!isTenantId(tenantId)) {
    throw new Error('tenant id must be lowercase letters, numbers, and single hyphens');
  }
  const baseUrl = normalizeBaseUrl(baseUrlInput);
  const name = argument('name') ?? tenantId;
  const tenantSecret = generateTenantSecret();
  const hashed = await hashTenantSecret(tenantSecret);
  try {
    await connectMongo(loadMongoUri());
  } catch {
    throw new Error('database connection failed');
  }
  try {
    await new MongoTenantRepository().insert({
      tenantId,
      name,
      baseUrl,
      secretSalt: hashed.secretSalt,
      secretHash: hashed.secretHash,
      active: true,
    });
  } catch (error) {
    if (error instanceof DuplicateTenantError) {
      throw new Error(`Tenant already exists: ${tenantId}`);
    }
    throw new Error('Tenant could not be created');
  }
  process.stdout.write(
    [
      'Tenant created.',
      `tenantId: ${tenantId}`,
      `baseUrl: ${baseUrl}`,
      `tenantSecret: ${tenantSecret}`,
      '',
      'Place these on that donut-pos server. The secret will not be shown again.',
      'SQUARE_BROKER_URL=https://square.channchealysek.com',
      `SQUARE_BROKER_TENANT_ID=${tenantId}`,
      `SQUARE_BROKER_SECRET=${tenantSecret}`,
      '',
    ].join('\n'),
  );
}

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) {
    return undefined;
  }
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) {
    return undefined;
  }
  return value;
}

main()
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : 'tenant provisioning failed';
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await disconnectMongo().catch(() => undefined);
  });
