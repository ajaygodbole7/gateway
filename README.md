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

- Java 21+
- Maven 3.8+
- Redis 6+ with TLS
- Azure subscription with Key Vault
- Ping Identity tenant


