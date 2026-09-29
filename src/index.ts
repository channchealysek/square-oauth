import type { Server } from 'node:http';
import { createApp } from './app.js';
import { loadServerConfig } from './config.js';
import { logger } from './logger.js';
import { connectMongo, disconnectMongo } from './repositories/models.js';
import { MongoAuthorizationRepository, MongoOAuthStateRepository, MongoTenantRepository } from './repositories/mongo.js';
import { SQUARE_API_VERSION } from './domain/squarePolicy.js';
import { SquareHttpClient } from './square/client.js';
import mongoose from 'mongoose';

async function main(): Promise<void> {
  const config = loadServerConfig();
  try {
    await connectMongo(config.mongodbUri);
  } catch {
    logger.error('database connection failed');
    process.exit(1);
  }
  const app = createApp({
    config,
    tenants: new MongoTenantRepository(),
    states: new MongoOAuthStateRepository(),
    authorizations: new MongoAuthorizationRepository(),
    square: new SquareHttpClient(config.applicationId, config.applicationSecret, config.redirectUri),
    isDatabaseHealthy: () => mongoose.connection.readyState === 1,
  });
  const server = app.listen(config.port, '0.0.0.0', () => {
    logger.info(
      {
        port: config.port,
        applicationId: config.applicationId,
        redirectUri: config.redirectUri,
        squareVersion: SQUARE_API_VERSION,
      },
      'square-oauth listening',
    );
  });
  installShutdown(server);
}

function installShutdown(server: Server): void {
  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    logger.info({ signal }, 'shutting down');
    server.close(() => {
      disconnectMongo()
        .catch(() => undefined)
        .finally(() => {
          process.exit(0);
        });
    });
    setTimeout(() => {
      process.exit(1);
    }, 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

process.on('unhandledRejection', (error: unknown) => {
  logger.error({ name: error instanceof Error ? error.name : 'unknown' }, 'unhandled rejection');
});

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : '';
  if (/^(Missing required|SQUARE_|MONGODB_|ENCRYPTION_|PORT )/.test(message)) {
    logger.error(message);
  } else {
    logger.error('startup failed');
  }
  process.exit(1);
});
