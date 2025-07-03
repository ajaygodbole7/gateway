# Security Gateway

OAuth2 authentication gateway with horizontal scaling support for Azure environments.

## Features

- OAuth2 + PKCE authentication flow with Ping Identity
- Azure Key Vault integration for secrets management
- Redis-based session storage with TLS
- APIM verdict endpoints for API Gateway integration
- Horizontal scaling with distributed locks
- Comprehensive security headers and CSRF protection


## Prerequisites

- Java 17+
- Maven 3.8+
- Redis 6+ with TLS
- Azure subscription with Key Vault
- Ping Identity tenant

## Configuration

### Environment Variables

```bash
# Azure Key Vault
AZURE_KEYVAULT_URI=https://your-keyvault.vault.azure.net
IDENTITY_ENDPOINT=<managed-identity-endpoint>
IDENTITY_HEADER=<managed-identity-header>

# Redis
REDIS_MODE=cluster
REDIS_CLUSTER_NODES=redis-0:6380,redis-1:6380,redis-2:6380
REDIS_SSL_ENABLED=true

# Ping Identity
PING_CLIENT_ID=your-client-id
PING_AUTH_URI=https://auth.pingidentity.com/as/authorization.oauth2
PING_TOKEN_URI=https://auth.pingidentity.com/as/token.oauth2
PING_JWKS_URI=https://auth.pingidentity.com/pf/JWKS
PING_ISSUER_URI=https://auth.pingidentity.com

# Application
FRONTEND_URL=https://app.company.com
