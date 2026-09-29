import mongoose, { Schema, type InferSchemaType } from 'mongoose';

const EncryptedBlobSchema = new Schema(
  {
    ciphertext: { type: String, required: true },
    iv: { type: String, required: true },
    tag: { type: String, required: true },
  },
  { _id: false },
);

const LocationSchema = new Schema(
  {
    locationId: { type: String, required: true },
    name: { type: String, required: true },
    status: { type: String, required: true },
    currency: { type: String, default: null },
  },
  { _id: false },
);

const TenantSchema = new Schema(
  {
    tenantId: { type: String, required: true, unique: true, immutable: true },
    name: { type: String, required: true },
    baseUrl: { type: String, required: true },
    secretSalt: { type: String, required: true },
    secretHash: { type: String, required: true },
    active: { type: Boolean, required: true, default: true },
  },
  {
    timestamps: true,
    toJSON: {
      transform(_doc, ret: Record<string, unknown>) {
        delete ret.secretSalt;
        delete ret.secretHash;
        return ret;
      },
    },
  },
);

const OAuthStateSchema = new Schema(
  {
    stateHash: { type: String, required: true, unique: true },
    tenantId: { type: String, required: true },
    returnPath: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    consumedAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

OAuthStateSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const SquareAuthorizationSchema = new Schema(
  {
    tenantId: { type: String, required: true, unique: true, immutable: true },
    merchantId: { type: String, default: null },
    environment: { type: String, required: true, enum: ['production'] },
    authorizationStatus: {
      type: String,
      required: true,
      enum: ['connected', 'disconnected', 'revoked'],
    },
    accessToken: { type: EncryptedBlobSchema, default: null },
    refreshToken: { type: EncryptedBlobSchema, default: null },
    accessTokenExpiresAt: { type: Date, default: null },
    accessTokenRefreshedAt: { type: Date, default: null },
    requestedScopes: { type: [String], required: true },
    locations: { type: [LocationSchema], required: true },
    selectedLocationId: { type: String, default: null },
    connectedAt: { type: Date, default: null },
    disconnectedAt: { type: Date, default: null },
    refreshLockUntil: { type: Date, default: null },
    refreshLockId: { type: String, default: null },
  },
  {
    timestamps: true,
    toJSON: {
      transform(_doc, ret: Record<string, unknown>) {
        delete ret.accessToken;
        delete ret.refreshToken;
        delete ret.refreshLockId;
        return ret;
      },
    },
  },
);

SquareAuthorizationSchema.index(
  { merchantId: 1 },
  {
    unique: true,
    partialFilterExpression: {
      authorizationStatus: 'connected',
      merchantId: { $type: 'string' },
    },
  },
);

export const TenantModel = mongoose.model('Tenant', TenantSchema);
export const OAuthStateModel = mongoose.model('OAuthState', OAuthStateSchema);
export const SquareAuthorizationModel = mongoose.model('SquareAuthorization', SquareAuthorizationSchema);

export type TenantDocument = InferSchemaType<typeof TenantSchema>;
export type OAuthStateDocument = InferSchemaType<typeof OAuthStateSchema>;
export type SquareAuthorizationDocument = InferSchemaType<typeof SquareAuthorizationSchema>;

export async function connectMongo(uri: string): Promise<void> {
  mongoose.set('strictQuery', true);
  await mongoose.connect(uri, {
    autoIndex: false,
    serverSelectionTimeoutMS: 10_000,
    maxPoolSize: 10,
  });
  await Promise.all([
    TenantModel.createIndexes(),
    OAuthStateModel.createIndexes(),
    SquareAuthorizationModel.createIndexes(),
  ]);
}

export async function disconnectMongo(): Promise<void> {
  await mongoose.disconnect();
}
