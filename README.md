# Authentication Service (`secure-vault-auth`)

The authentication and identity microservice for the **Digital Notes / secure-vault** platform. It owns user sign-up and login, issues and validates the JWTs that every other service in the platform trusts, supports OAuth2 social login (GitHub & Google), TOTP-based two-factor authentication, and the role-upgrade / delegate-bootstrap workflows. Role data itself lives in a separate **roles-service**, which this service talks to over a Feign client.

---

## Tech stack

| | |
|---|---|
| Language / runtime | Java 21 |
| Framework | Spring Boot 4.0.6 (Spring Cloud 2025.1.1) |
| Security | Spring Security, JWT (`jjwt` 0.12.7), OAuth2 client |
| 2FA | `com.warrenstrange:googleauth` (TOTP / Google Authenticator) |
| Persistence | Spring Data JPA + Hibernate, PostgreSQL |
| Inter-service calls | Spring Cloud OpenFeign (→ roles-service) |
| Mapping | ModelMapper |
| Email | Spring Mail (Gmail SMTP) |
| API docs | springdoc-openapi (Swagger UI) |
| Build | Maven (wrapper included) |

---

## How it fits in the platform

```
                 ┌─────────────────┐
  Browser / UI ─▶│  Authentication │──Feign──▶  roles-service
                 │   (this service)│            (role lookup, role mapping,
                 └────────┬────────┘             token introspection)
                          │ issues JWT
                          ▼
        notes-service, ai-core-service, roles-service …
        all validate the SAME JWT (shared JWT_SECRET)
```

> **Important:** `JWT_SECRET` **must be identical** across Authentication, notes, roles, and ai-core-service, or cross-service tokens won't validate. (See `ci/deploy.sh`.)

---

## Running locally

### Prerequisites
- JDK 21
- PostgreSQL (a database reachable via the JDBC URL below)
- Maven (or use the bundled `./mvnw` / `mvnw.cmd`)

### Environment variables

The service reads everything from environment variables (see `src/main/resources/application.yml`). At minimum:

| Variable | Description |
|---|---|
| `SPRING_DATASOURCE_URL` | JDBC URL, e.g. `jdbc:postgresql://localhost:5432/digital-notes?currentSchema=secure-vault` |
| `SPRING_DATASOURCE_USERNAME` | Postgres username (e.g. `postgres`) |
| `SPRING_DATASOURCE_PASSWORD` | Postgres password |
| `JWT_SECRET_KEY` | HMAC secret — **must match all other services** |
| `JWT_EXPIRATION` | Token lifetime in ms (e.g. `1800000` = 30 min) |
| `ROLE_SERVICE_KEY` | Shared internal secret for auth ↔ roles calls |
| `ROLES_SERVICE_URL` | Base URL of roles-service (Feign client target) |
| `DELEGATE_BOOTSTRAP_KEY` | Secret for the first-delegate/admin bootstrap signup |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth app credentials |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth app credentials |
| `MAIL_USERNAME` / `MAIL_PASSWORD` | Gmail SMTP sender + app password |
| `FRONTEND_URL` | Public UI URL (used in OAuth redirect + email links) |

### Start it

```bash
# Windows (PowerShell)
.\mvnw.cmd spring-boot:run

# Linux / macOS
./mvnw spring-boot:run
```

The service starts on **port `3211`** with context path **`/authentication`**, so it responds at:

```
http://localhost:3211/authentication/...
```

Swagger UI (when enabled): `http://localhost:3211/authentication/swagger.html`

---

## API overview

All paths below are relative to the context path `/authentication`. Endpoints under `/api/user/public/**`, `/api/user/**`, and `/api/delegate/signup-delegate` are public; everything else requires a `Bearer` JWT, and several endpoints enforce roles via `@PreAuthorize`.

### User auth & account — `/api/user`

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/public/signUp` | public | Register a new user |
| `POST` | `/public/login` | public | Log in; returns user + JWT |
| `GET`  | `/public/validate?token=` | public | Validate a JWT (boolean) |
| `GET`  | `/public/extractUserId?token=` | public | Extract userId from a JWT |
| `POST` | `/public/verify-2fa-login?code=&jwtToken=` | public | Complete the 2FA step during login |
| `GET`  | `/public/introspect` | Bearer | Token introspection (active / username / roles) |
| `POST` | `/enable-2fa` | Bearer | Generate a 2FA secret, returns QR-code URL |
| `POST` | `/disable-2fa` | Bearer | Disable 2FA for the current user |
| `POST` | `/verify-2fa?code=` | Bearer | Verify a TOTP code and enable 2FA |
| `GET`  | `/2fa-status` | Bearer | Whether 2FA is enabled for the current user |
| `GET`  | `/allUsers` | Bearer · `DELEGATE` | List all users |
| `GET`  | `/getUserByUsername?username=` | Bearer | Look up a user by username |
| `GET`  | `/getUserByUserId?userId=` | Bearer | Look up a user by id |

### Admin — `/api/admin`

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/assign-role?userId=&roleType=` | Bearer · `ADMIN` | Assign a role (`ROLE_*`) to a user (delegates to roles-service) |

### Role upgrade — `/api/role-upgrade`

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/request-admin` | Bearer · `CUSTOMER` | Raise a request to be upgraded to admin |
| `GET`  | `/myRequests` | Bearer | View your own upgrade requests |
| `GET`  | `/pending` | Bearer · `DELEGATE` | View pending upgrade requests |
| `POST` | `/approve?requestId=` | Bearer · `DELEGATE` | Approve a request |
| `POST` | `/reject?requestId=` | Bearer · `DELEGATE` | Reject a request |

### Delegate bootstrap — `/api/delegate`

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/signup-delegate` | `X-Delegate-Bootstrap-Key` header | Bootstrap-create a delegate/admin account |

### OAuth2 social login

- Entry points: `/oauth2/authorization/github`, `/oauth2/authorization/google`
- On success, `OAuth2LoginSuccessHandler` finds-or-creates the user (defaulting them to `ROLE_CUSTOMER` via roles-service), issues a JWT, and redirects to:
  `${FRONTEND_URL}/notes/oauth2/redirect?token=<jwt>`

---

## Security model

- **Stateless** — no server sessions; every request is authenticated from the `Authorization: Bearer <jwt>` header by `JwtAuthenticationFilter`.
- **CSRF disabled** (token-based API), **CORS** restricted to `http://localhost:3000` (GET/POST) in `SecurityConfiguration`.
- **Method-level RBAC** via `@EnableMethodSecurity` + `@PreAuthorize` (roles `ADMIN`, `DELEGATE`, `CUSTOMER`).
- **Roles are not stored on the user row** — the `roles` field on `Users` is `@Transient` and fetched live from roles-service.
- **2FA** is TOTP-based; secrets are generated server-side and provisioned via a QR-code URL.

---

## Data model (`users` table)

Key fields on the `Users` entity: `userId` (PK, app-generated string), unique `username` and `email`, hashed `password` (`@JsonIgnore`), account/credentials status flags, `twoFactorSecret` + `isTwoFactorEnabled`, `signUpMethod` (e.g. `github`/`google`/local), and audit timestamps. Roles are resolved at runtime, not persisted here.

---

## Build, test & package

```bash
./mvnw clean test       # run tests
./mvnw clean package    # build the executable jar → target/*.jar
java -jar target/Authentication-0.0.1-SNAPSHOT.jar
```

### Docker

A multi-stage `Dockerfile` is provided (Maven build stage → JRE-only runtime). It exposes port `3211`.

```bash
docker build -t secure-vault-authentication .
docker run -p 3211:3211 --env-file .env secure-vault-authentication
```

---

## Deployment

CI/CD lives under `ci/` and the root manifests:

- `Jenkinsfile` / `bitbucket-pipelines.yml` — pipeline definitions
- `ci/deploy.sh` — renders k8s manifests with `sed` and ships them to a k3s cluster (inside an LXD container on a VPS) over SSH; `ci/deploy-remote.sh` applies them
- `deployment.yml`, `service.yml`, `ingress.yml` — Kubernetes manifests (templated with `${VAR}` placeholders)
- `ci/nginx/authentication.location.conf` — host nginx reverse-proxy snippet

See the header comment in `ci/deploy.sh` for the full list of required deployment variables.

---

## Project layout

```
src/main/java/com/application/authentication/
├── AuthenticationApplication.java     # Spring Boot entry point
├── configuration/                     # Security, JWT filter, CORS, OAuth2 handler, Swagger, Feign interceptor
├── controller/                        # REST endpoints (user, admin, delegate, role-upgrade, introspection)
├── service/                           # Auth, JWT, TOTP/2FA, role-upgrade business logic
├── feignService/RolesClient.java      # Feign client → roles-service
├── model/                             # JPA entities (Users, Roles, PasswordResetToken, RoleUpgradeRequest)
├── repository/                        # Spring Data JPA repositories
├── dtos/ · request/                   # Request/response payloads
├── exceptions/                        # GlobalExceptionHandler + custom exceptions
└── utils/                             # ApiResponse, AuthUtils, Constants, EmailService
```
