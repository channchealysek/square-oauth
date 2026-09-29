import { loadMongoUri } from '../src/config.js';
import { generateTenantSecret, hashTenantSecret } from '../src/crypto/secrets.js';
import { isTenantId } from '../src/domain/urls.js';
import { connectMongo, disconnectMongo } from '../src/repositories/models.js';
import { MongoTenantRepository } from '../src/repositories/mongo.js';

async function main(): Promise<void> {
  const tenantId = argument('id');
  if (!tenantId) {
    throw new Error('Usage: npm run tenant:rotate-secret -- --id <tenant-id>');
  }
  if (!isTenantId(tenantId)) {
    throw new Error('tenant id must be lowercase letters, numbers, and single hyphens');
  }
  const tenantSecret = generateTenantSecret();
  const hashed = await hashTenantSecret(tenantSecret);
  try {
    await connectMongo(loadMongoUri());
  } catch {
    throw new Error('database connection failed');
  }
  const replaced = await new MongoTenantRepository().replaceSecret(tenantId, hashed.secretSalt, hashed.secretHash);
  if (!replaced) {
    throw new Error(`Tenant not found: ${tenantId}`);
  }
  process.stdout.write(
    [
      'Tenant secret rotated.',
      `tenantId: ${tenantId}`,
      `tenantSecret: ${tenantSecret}`,
      '',
      'Replace the secret in that donut-pos server environment now.',
      'The previous secret no longer works. This value will not be shown again.',
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
    const message = error instanceof Error ? error.message : 'tenant secret rotation failed';
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await disconnectMongo().catch(() => undefined);
  });
