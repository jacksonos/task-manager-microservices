# Task Manager MVP — Design Spec
Date: 2026-10-01
Status: approved sections 1-4 (Section 3 revised for refresh + pagination)

## 1. Goal
Full-stack MVP with three microservices: auth-service + task-service (Spring Boot, Java 21) + web (React/Vite). Postgres, Docker Compose.

## 2. Architecture (Option A)
```
[React Vite :5173 / nginx :3000] --/auth/*--> [auth-service :8081] --> [postgres:5432/authdb]
                                 --/tasks/*-> [task-service :8082] --> [postgres:5432/taskdb]
```
- Repo: `auth-service/`, `task-service/`, `web/`, `docker-compose.yml`, `README.md`
- Stack: Java 21, Spring Boot 3.3.x (web, validation, data-jpa, security, postgres driver, jjwt), React Vite (fetch, no UI lib), Postgres 16, nginx for prod web.
- Ports: 8081, 8082, 5173 dev / 3000 prod, 5432.
- Env: `JWT_SECRET` (shared), `DB_URL_AUTH`, `DB_URL_TASKS`, `VITE_AUTH_URL`, `VITE_TASK_URL`.

## 3. Components
- auth-service:
  - `POST /api/auth/register {username,password}` -> 201 or 409. `users(id, username unique, password_hash)`.
  - `POST /api/auth/login {username,password}` -> `{accessToken (15m HS256, sub=username), refreshToken (7d opaque UUID), username}` or 401.
  - `POST /api/auth/refresh {refreshToken}` -> rotate: revoke old, issue new pair. 401 if expired/revoked.
  - `POST /api/auth/logout {refreshToken}` -> revoke.
  - `refresh_tokens(id, username, token_hash, expires_at, revoked)`.
- task-service:
  - `GET /api/tasks?page=0&size=10&sort=createdAt,desc` -> `{content[], page, size, totalElements, totalPages}`, owner-scoped.
  - `POST /api/tasks {title}` -> 201. `PUT /api/tasks/{id} {title,done}`, `DELETE /api/tasks/{id}`. 403 if not owner, 404 if missing.
  - `GET /api/health` -> `{status:"UP"}`.
  - `tasks(id, owner, title, done, created_at)`. JwtAuthFilter validates access token with same `JWT_SECRET`.
- web:
  - Pages: Login / Register / Tasks (conditional render, no router lib).
  - `api.js`: authApi + taskApi bases from `.env`, stores `accessToken + refreshToken + username` in localStorage, auto-refresh on 401 with single retry + request queue.
  - Tasks page: list + create + toggle + delete + pager (prev/next, size 10).

## 4. Data flow
register -> login (store pair) -> `GET /tasks` with `Bearer accessToken` -> on 401 try refresh -> retry -> CRUD re-renders. Logout revokes refresh.

## 5. Error handling
- Backend `@RestControllerAdvice` -> `{message}` with 400 validation, 401 bad creds/invalid token, 409 user exists, 403/404 tasks.
- Frontend: inline error, redirect to login if refresh fails, confirm delete.

## 6. Testing (minimal)
- curl smoke: register/login/refresh/paged fetch; `docker compose ps`; manual UI check. No JUnit/Vitest in MVP.

## 7. Files + run
```
auth-service/src/main/.../AuthController, JwtUtil, SecurityConfig, User, RefreshToken
task-service/src/main/.../TaskController, JwtAuthFilter, Task
web/src/App.jsx, api.js, main.jsx + .env + nginx.conf
docker-compose.yml (postgres + auth + tasks + web)
```
- `docker compose up --build` -> web http://localhost:3000, auth http://localhost:8081/api/auth/*, tasks http://localhost:8082/api/tasks.
- Local dev: `./mvnw spring-boot:run` each service, `npm run dev` for web.

## 8. Explicitly skipped
Refresh reuse detection beyond revoke, pagination filters/search, Eureka/Gateway, shared lib, CI, JUnit/Vitest. Add when needed.

## Spec self-review
- No TBD/TODO. Architecture matches components. Single-plan scope. Access vs refresh lifetimes explicit, rotation explicit, pagination response shape explicit.
