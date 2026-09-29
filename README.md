# square-oauth

Central production OAuth broker for the Square application `pos systems`. Every donut-pos merchant uses one callback:

`https://square.channchealysek.com/oauth/callback`

The container listens on port **3436**. Nginx Proxy Manager forwards `square.channchealysek.com` to `http://square-oauth:3436`.

The Square application secret and seller refresh tokens stay in this service. A customer donut-pos server authenticates with its own tenant secret. Customers do not need the Developer Console, the application secret, Android SHA changes, or access to any other merchant.

The existing Android package `com.maxdonuts.customer_self_order` already has its production Mobile Payments SDK signature. Do not register another signature per merchant, and do not change the Flutter app from this service.

This service does not create payments and does not accept card data.

## Deployment order

1. Create the GitHub repository.
2. Push the square-oauth source.
3. Configure the image build and registry. Prefer GHCR.
4. Build and publish the Docker image.
5. Configure MongoDB.
6. Generate `ENCRYPTION_KEY`.
7. Deploy square-oauth with Portainer. The process listens on port 3436.
8. Verify the container: `GET /health` at `http://square-oauth:3436/health`.
9. Connect Nginx Proxy Manager to `square-oauth:3436`. Do this only after the container exists.
10. Enable SSL.
11. Verify `https://square.channchealysek.com/health`.
12. Set the Square Developer production redirect URL to `https://square.channchealysek.com/oauth/callback`.
13. Provision the Max Donuts tenant.
14. Add the broker tenant credentials to the Max Donuts donut-pos server.
15. Modify donut-pos to use the broker.
16. Test Connect Square Account.
17. Test the existing customer_self_order reader.

Steps 13–17 are later work. This repository does not perform them.

## GitHub

```bash
cd D:\projects\square-oauth
git init
git add .
git status
git commit -m "Add the central Square OAuth broker."
git branch -M main
git remote add origin git@github.com:OWNER/square-oauth.git
git push -u origin main
```

Replace `OWNER` with the GitHub account or organization. Confirm `git status` does not list `.env`.

`.github/workflows/ci.yml` runs `npm ci`, `npm run typecheck`, and `npm test` on push and pull request. It does not build an image, deploy, or call Square.

## Docker image

```bash
docker build -t ghcr.io/OWNER/square-oauth:1.0.0 .
docker push ghcr.io/OWNER/square-oauth:1.0.0
```

The image exposes port 3436. It does not contain secrets. `PORT` defaults to 3436 inside the image and can be overridden at runtime.

## Encryption key

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Store the value in Portainer as `ENCRYPTION_KEY`. Seller access and refresh tokens are encrypted with AES-256-GCM. The IV and authentication tag are stored with the ciphertext, and the tenant ID is bound as additional authenticated data.

Replacing `ENCRYPTION_KEY` makes stored seller tokens unreadable. Set the new key, then connect each seller again. There is no migration that decrypts old tokens.

## MongoDB

Use a dedicated database. Startup creates indexes with `createIndexes` only.

```text
MONGODB_URI=mongodb://USER:PASSWORD@mongo-host:27017/square-oauth?authSource=admin
```

Collections: `tenants`, `oauthstates`, `squareauthorizations`.

OAuth state expires about 10 minutes after creation. A TTL index removes those documents. The callback also rejects expired and replayed states immediately.

## Portainer

Do not hard-code a public IP. Put every secret in the Portainer environment, not in the Dockerfile or Git repository.

```text
NODE_ENV=production
PORT=3436
MONGODB_URI=<secret>
SQUARE_APPLICATION_ID=<production application id, sq0idp-...>
SQUARE_APPLICATION_SECRET=<secret>
SQUARE_REDIRECT_URI=https://square.channchealysek.com/oauth/callback
ENCRYPTION_KEY=<secret>
```

Container name: `square-oauth`.

Restart policy: unless stopped.

Command: the image already runs `node dist/index.js` and binds `0.0.0.0:3436`.

Nginx Proxy Manager and this container must share a Docker network so the hostname `square-oauth` resolves. Attach both to that network. Do not publish port 3436 on the public host interface when they share a network.

If they are not on the same Docker network, set the proxy forward host to the reachable Docker host address that can open this container's port 3436. Choose that address from the host's own Docker network settings. This document does not guess an IP.

### A. GHCR image

In Portainer, add a container or stack that pulls `ghcr.io/OWNER/square-oauth:1.0.0`.

```yaml
services:
  square-oauth:
    image: ghcr.io/OWNER/square-oauth:1.0.0
    container_name: square-oauth
    restart: unless-stopped
    environment:
      NODE_ENV: production
      PORT: "3436"
      MONGODB_URI: ${MONGODB_URI}
      SQUARE_APPLICATION_ID: ${SQUARE_APPLICATION_ID}
      SQUARE_APPLICATION_SECRET: ${SQUARE_APPLICATION_SECRET}
      SQUARE_REDIRECT_URI: https://square.channchealysek.com/oauth/callback
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}
    networks:
      - proxy

networks:
  proxy:
    external: true
```

`proxy` must be the external network Nginx Proxy Manager already uses. If that network has another name, use that name. Do not invent a public IP.

### B. Portainer stack build from GitHub

If the Portainer stack is connected to the Git repository, it can build the Dockerfile:

```yaml
services:
  square-oauth:
    build: .
    image: square-oauth:1.0.0
    container_name: square-oauth
    restart: unless-stopped
    environment:
      NODE_ENV: production
      PORT: "3436"
      MONGODB_URI: ${MONGODB_URI}
      SQUARE_APPLICATION_ID: ${SQUARE_APPLICATION_ID}
      SQUARE_APPLICATION_SECRET: ${SQUARE_APPLICATION_SECRET}
      SQUARE_REDIRECT_URI: https://square.channchealysek.com/oauth/callback
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}
    networks:
      - proxy

networks:
  proxy:
    external: true
```

Prefer option A when a registry is available. GitHub Actions in this repo does not publish the image.

## Nginx Proxy Manager

Create the proxy host after the container is running.

| Field | Value |
| --- | --- |
| Domain Names | `square.channchealysek.com` |
| Scheme | `http` |
| Forward Hostname / IP | `square-oauth` |
| Forward Port | `3436` |
| Access List | Publicly Accessible |
| Block Common Exploits | ON |
| Websockets Support | OFF |
| Cache Assets | OFF |

SSL:

- Request a new SSL Certificate
- Let's Encrypt
- Force SSL: ON
- HTTP/2 Support: ON

Health check from another container on the same network:

```text
http://square-oauth:3436/health
```

Public check after SSL:

```text
https://square.channchealysek.com/health
```

Expected body while MongoDB is connected:

```json
{"ok":true,"service":"square-oauth"}
```

The app sets `trust proxy` to `1` for this single proxy hop. Keep port 3436 off the public host interface. A client that can connect straight to the container can spoof `X-Forwarded-For`.

## Square Developer configuration

Production redirect URL, once, for every merchant:

```text
https://square.channchealysek.com/oauth/callback
```

Use the production application ID (`sq0idp-...`) and production application secret. Sandbox IDs are rejected at startup.

Authorization uses `https://connect.squareup.com/oauth2/authorize` with `session=false` and these scopes:

- `MERCHANT_PROFILE_READ`
- `PAYMENTS_READ`
- `PAYMENTS_WRITE`
- `PAYMENTS_WRITE_IN_PERSON`
- `DEVICE_CREDENTIAL_MANAGEMENT`

No per-customer redirect URL is required. Do not change the Android Mobile Payments SDK signature for `com.maxdonuts.customer_self_order`.

Square's ObtainToken response does not list granted scopes. This service stores the scopes it requested.

## Tenant provisioning

Run this later, from an operator machine that can reach MongoDB. Node.js 20 or newer:

```bash
npm run tenant:create -- --id max-donuts --url https://maxdonut.channchealysek.com
```

PowerShell:

```powershell
$env:MONGODB_URI="mongodb://USER:PASSWORD@mongo-host:27017/square-oauth?authSource=admin"
npm run tenant:create -- --id max-donuts --url https://maxdonut.channchealysek.com
```

The command checks the tenant ID and HTTPS URL, rejects duplicates, stores a scrypt hash, and prints the plaintext secret once.

Place these on that customer's donut-pos server:

```text
SQUARE_BROKER_URL=https://square.channchealysek.com
SQUARE_BROKER_TENANT_ID=max-donuts
SQUARE_BROKER_SECRET=<secret printed once>
```

Do not copy `SQUARE_APPLICATION_SECRET` or `ENCRYPTION_KEY` onto donut-pos.

Rotate a leaked tenant secret with:

```bash
npm run tenant:rotate-secret -- --id max-donuts
```

## What donut-pos must do next

This is a report for a later change. Do not implement it in this repository.

On the store server, send `Authorization: Bearer <SQUARE_BROKER_SECRET>` to `SQUARE_BROKER_URL`.

1. Payment Settings calls `POST /api/tenants/:tenantId/oauth/start` and redirects the admin browser to `authorizationUrl`. Avoid logging that URL. It contains the one-time state.
2. Read `GET /api/tenants/:tenantId/square/status`.
3. Change location with `PUT /api/tenants/:tenantId/square/location` and `{ "locationId": "..." }`.
4. After the existing trusted-device check, and only when that device is allowed to use the reader, call `POST /api/tenants/:tenantId/mobile-payments/authorization`. Pass `accessToken` and `locationId` into the Mobile Payments SDK `AuthorizationManager`. Discard the access token after that call. Do not store it as Flutter configuration.
5. Before marking an order paid, call `POST /api/tenants/:tenantId/payments/verify`. Change the local order to paid only when `verified` is true.
6. Disconnect with `POST /api/tenants/:tenantId/square/disconnect`.

The tablet continues to talk only to its donut-pos server. This broker does not decide tablet trust, device type, `kioskSquareReaderEnabled`, or `allowCardReader`.

## Routes

| Method | Path | Caller |
| --- | --- | --- |
| GET | `/health` | Container and proxy health check |
| POST | `/api/tenants/:tenantId/oauth/start` | That tenant's donut-pos server. Optional body `{ "returnPath" }` |
| GET | `/oauth/callback` | Square redirect. HTML result only |
| GET | `/api/tenants/:tenantId/square/status` | That tenant |
| PUT | `/api/tenants/:tenantId/square/location` | That tenant |
| POST | `/api/tenants/:tenantId/square/disconnect` | That tenant |
| POST | `/api/tenants/:tenantId/mobile-payments/authorization` | That tenant |
| POST | `/api/tenants/:tenantId/payments/verify` | That tenant |

`POST /payments/verify` reads an existing payment. It does not create one. A client field such as `paid: true` is rejected. Verification succeeds only when Square reports `COMPLETED` and the amount, currency, selected location, and optional `referenceId` or `checkoutAttemptId` match. `checkoutAttemptId` is compared with Square `Payment.reference_id`.

The first selected location is the lexicographically first location whose status is `ACTIVE`.

## Mobile Payments authorization

Square's Mobile Payments SDK authorizes with the seller OAuth access token and a location ID. This route returns:

```json
{
  "available": true,
  "applicationId": "sq0idp-...",
  "locationId": "...",
  "accessToken": "...",
  "environment": "production"
}
```

donut-pos may relay that access token only to an already authorized trusted customer_self_order device, and only for `AuthorizationManager`. It must not be saved as permanent Flutter configuration. The refresh token and application secret are not returned.

Square recommends a 24-hour short-lived access token when a credential is handed to a mobile client. This route returns the current seller access token, refreshed when 23 days or less remain. It does not mint a separate short-lived token.

The Mobile Payments SDK is for attended devices. Square prohibits unattended kiosks. SDK 2.1 and later also require the application signature that is already registered for `com.maxdonuts.customer_self_order`.

## Token refresh

Square access tokens last 30 days. This service refreshes when 23 days or less remain. A per-tenant lock stops two refreshes of the same seller at once. A replacement refresh token from Square replaces the stored one. Revoked authorization clears the stored seller tokens and leaves the tenant row in place.

## Local checks

```bash
npm install
npm run typecheck
npm test
```

Tests use in-memory repositories and a fake Square client. They do not call Square production.
