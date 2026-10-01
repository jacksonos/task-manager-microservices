# Task Manager MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build task-manager MVP with auth-service + task-service + React web running via Docker Compose.

**Architecture:** Option A from spec — two stateless Spring Boot APIs sharing only JWT_SECRET env, Postgres with authdb/taskdb, React SPA calling both directly with auto-refresh. No gateway, no shared lib.

**Tech Stack:** Java 21, Spring Boot 3.3.x, Postgres 16, React Vite, jjwt 0.12.x, nginx, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-01-task-manager-mvp-design.md`

## Global Constraints

- Java 21 exactly, Spring Boot 3.3.x.
- Postgres 16, databases `authdb` + `taskdb`.
- Ports: auth 8081, tasks 8082, web 3000 prod / 5173 dev, pg 5432.
- Env `JWT_SECRET` identical for both backends, min 32 chars.
- Access token 15m HS256 sub=username, refresh token 7d opaque UUID SHA-256 stored.
- Tasks paged `GET /api/tasks?page=0&size=10&sort=createdAt,desc`.
- No Eureka/Gateway/shared jar/CI/JUnit suites — curl + compose smoke only.

---

### Task 1: auth-service

**Files:**
- Create: `auth-service/pom.xml`
- Create: `auth-service/src/main/resources/application.yml`
- Create: `auth-service/src/main/java/com/tasks/auth/AuthServiceApplication.java`
- Create: `auth-service/src/main/java/com/tasks/auth/User.java`
- Create: `auth-service/src/main/java/com/tasks/auth/RefreshToken.java`
- Create: `auth-service/src/main/java/com/tasks/auth/UserRepository.java`
- Create: `auth-service/src/main/java/com/tasks/auth/RefreshTokenRepository.java`
- Create: `auth-service/src/main/java/com/tasks/auth/JwtUtil.java`
- Create: `auth-service/src/main/java/com/tasks/auth/SecurityConfig.java`
- Create: `auth-service/src/main/java/com/tasks/auth/AuthController.java`
- Create: `auth-service/Dockerfile`

**Interfaces:**
- Consumes: `JWT_SECRET` env, `authdb` JDBC.
- Produces: `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/refresh`, `POST /api/auth/logout` used by Task 3 web.

- [ ] **Step 1: Write pom + config**

```xml
<!-- auth-service/pom.xml -->
<project xmlns="http://maven.apache.org/POM/4.0.0">
<modelVersion>4.0.0</modelVersion>
<parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.3.5</version></parent>
<groupId>com.tasks</groupId><artifactId>auth-service</artifactId><version>0.1.0</version>
<properties><java.version>21</java.version></properties>
<dependencies>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-validation</artifactId></dependency>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-jpa</artifactId></dependency>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>
<dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><scope>runtime</scope></dependency>
<dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-api</artifactId><version>0.12.6</version></dependency>
<dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-impl</artifactId><version>0.12.6</version><scope>runtime</scope></dependency>
<dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-jackson</artifactId><version>0.12.6</version><scope>runtime</scope></dependency>
</dependencies>
</project>
```

```yaml
# auth-service/src/main/resources/application.yml
server:
  port: 8081
spring:
  datasource:
    url: ${DB_URL:jdbc:postgresql://localhost:5432/authdb}
    username: ${DB_USER:postgres}
    password: ${DB_PASS:postgres}
  jpa:
    hibernate:
      ddl-auto: update
```

- [ ] **Step 2: Write entities + repos + app**

```java
// AuthServiceApplication.java
package com.tasks.auth;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication
public class AuthServiceApplication {
  public static void main(String[] args) { SpringApplication.run(AuthServiceApplication.class, args); }
}
```

```java
// User.java
package com.tasks.auth;
import jakarta.persistence.*;
@Entity @Table(name = "users")
public class User {
  @Id @GeneratedValue(strategy = GenerationType.IDENTITY) public Long id;
  @Column(unique = true, nullable = false) public String username;
  @Column(name = "password_hash", nullable = false) public String passwordHash;
}
```

```java
// RefreshToken.java
package com.tasks.auth;
import jakarta.persistence.*;
import java.time.Instant;
@Entity @Table(name = "refresh_tokens")
public class RefreshToken {
  @Id @GeneratedValue(strategy = GenerationType.IDENTITY) public Long id;
  @Column(nullable = false) public String username;
  @Column(name = "token_hash", nullable = false, unique = true) public String tokenHash;
  @Column(name = "expires_at", nullable = false) public Instant expiresAt;
  @Column(nullable = false) public boolean revoked = false;
}
```

```java
// UserRepository.java
package com.tasks.auth;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);
  boolean existsByUsername(String username);
}
```

```java
// RefreshTokenRepository.java
package com.tasks.auth;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
  Optional<RefreshToken> findByTokenHash(String tokenHash);
}
```

- [ ] **Step 3: Write JwtUtil + SecurityConfig**

```java
// JwtUtil.java
package com.tasks.auth;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Date;
import java.util.HexFormat;
@Component
public class JwtUtil {
  private final SecretKey key;
  public JwtUtil(@Value("${JWT_SECRET:change-me-to-32-chars-minimum-secret!!}") String secret) {
    // ponytail: shared env secret copy, per-service JWKS if multi-team matters
    this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
  }
  public String access(String username) {
    long now = System.currentTimeMillis();
    return Jwts.builder().subject(username).issuedAt(new Date(now))
      .expiration(new Date(now + 15 * 60 * 1000)).signWith(key).compact();
  }
  public String username(String token) {
    return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload().getSubject();
  }
  public static String sha256(String raw) {
    try {
      byte[] d = MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(d);
    } catch (Exception e) { throw new IllegalStateException(e); }
  }
}
```

```java
// SecurityConfig.java
package com.tasks.auth;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
@Configuration
public class SecurityConfig {
  @Bean SecurityFilterChain chain(HttpSecurity h) throws Exception {
    return h.csrf(c -> c.disable()).authorizeHttpRequests(a -> a.anyRequest().permitAll()).build();
  }
  @Bean PasswordEncoder encoder() { return new BCryptPasswordEncoder(); }
}
```

- [ ] **Step 4: Write AuthController**

```java
// AuthController.java
package com.tasks.auth;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
@RestController @RequestMapping("/api/auth")
public class AuthController {
  public record AuthReq(@NotBlank String username, @NotBlank String password) {}
  public record RefreshReq(@NotBlank String refreshToken) {}
  private final UserRepository users; private final RefreshTokenRepository tokens;
  private final PasswordEncoder enc; private final JwtUtil jwt;
  public AuthController(UserRepository u, RefreshTokenRepository t, PasswordEncoder e, JwtUtil j) {
    users = u; tokens = t; enc = e; jwt = j;
  }
  @PostMapping("/register")
  public ResponseEntity<?> register(@Valid @RequestBody AuthReq r) {
    if (users.existsByUsername(r.username())) throw new ResponseStatusException(HttpStatus.CONFLICT, "user exists");
    User u = new User(); u.username = r.username(); u.passwordHash = enc.encode(r.password());
    users.save(u); return ResponseEntity.status(201).body(Map.of("username", u.username));
  }
  @PostMapping("/login")
  public Map<?, ?> login(@Valid @RequestBody AuthReq r) {
    User u = users.findByUsername(r.username()).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "bad creds"));
    if (!enc.matches(r.password(), u.passwordHash)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "bad creds");
    return issue(u.username);
  }
  @PostMapping("/refresh")
  public Map<?, ?> refresh(@Valid @RequestBody RefreshReq r) {
    RefreshToken t = tokens.findByTokenHash(JwtUtil.sha256(r.refreshToken()))
      .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "bad refresh"));
    if (t.revoked || t.expiresAt.isBefore(Instant.now())) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "bad refresh");
    t.revoked = true; tokens.save(t);
    return issue(t.username);
  }
  @PostMapping("/logout")
  public Map<?, ?> logout(@Valid @RequestBody RefreshReq r) {
    tokens.findByTokenHash(JwtUtil.sha256(r.refreshToken())).ifPresent(t -> { t.revoked = true; tokens.save(t); });
    return Map.of("ok", true);
  }
  private Map<?, ?> issue(String username) {
    String raw = UUID.randomUUID().toString();
    RefreshToken t = new RefreshToken();
    t.username = username; t.tokenHash = JwtUtil.sha256(raw);
    t.expiresAt = Instant.now().plus(7, ChronoUnit.DAYS);
    tokens.save(t);
    return Map.of("accessToken", jwt.access(username), "refreshToken", raw, "username", username);
  }
  @RestControllerAdvice
  static class Advice {
    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<?> handle(ResponseStatusException e) {
      return ResponseEntity.status(e.getStatusCode()).body(Map.of("message", e.getReason()));
    }
  }
}
```

```dockerfile
# auth-service/Dockerfile
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY target/auth-service-0.1.0.jar app.jar
ENTRYPOINT ["java","-jar","app.jar"]
```

- [ ] **Step 5: Verify + commit**

Run: `mvn -pl auth-service package -DskipTests; DB_URL=jdbc:postgresql://localhost:5432/authdb JWT_SECRET=test-secret-min-32-chars-1234567890 java -jar auth-service/target/auth-service-0.1.0.jar`
Expected: starts on 8081.
Run: `curl -s -X POST localhost:8081/api/auth/register -H "Content-Type: application/json" -d "{\"username\":\"u1\",\"password\":\"pass1234\"}"; echo; curl -s -X POST localhost:8081/api/auth/login -H "Content-Type: application/json" -d "{\"username\":\"u1\",\"password\":\"pass1234\"}"; echo`
Expected: 201 then JSON with accessToken + refreshToken.

```bash
git add auth-service
git commit -m "feat: add auth-service with JWT refresh"
```

### Task 2: task-service

**Files:**
- Create: `task-service/pom.xml` (same parent, artifact task-service)
- Create: `task-service/src/main/resources/application.yml`
- Create: `task-service/src/main/java/com/tasks/tasks/TaskServiceApplication.java`
- Create: `task-service/src/main/java/com/tasks/tasks/Task.java`
- Create: `task-service/src/main/java/com/tasks/tasks/TaskRepository.java`
- Create: `task-service/src/main/java/com/tasks/tasks/JwtAuthFilter.java`
- Create: `task-service/src/main/java/com/tasks/tasks/SecurityConfig.java`
- Create: `task-service/src/main/java/com/tasks/tasks/TaskController.java`
- Create: `task-service/Dockerfile`

**Interfaces:**
- Consumes: `JWT_SECRET` (same value as Task 1), `taskdb` JDBC.
- Produces: `GET/POST /api/tasks`, `PUT/DELETE /api/tasks/{id}`, `GET /api/health` used by Task 3.

- [ ] **Step 1: Write pom + config + entity**

```xml
<!-- task-service/pom.xml: same as auth pom but artifactId task-service -->
<project xmlns="http://maven.apache.org/POM/4.0.0">
<modelVersion>4.0.0</modelVersion>
<parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.3.5</version></parent>
<groupId>com.tasks</groupId><artifactId>task-service</artifactId><version>0.1.0</version>
<properties><java.version>21</java.version></properties>
<dependencies>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-validation</artifactId></dependency>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-jpa</artifactId></dependency>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>
<dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><scope>runtime</scope></dependency>
<dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-api</artifactId><version>0.12.6</version></dependency>
<dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-impl</artifactId><version>0.12.6</version><scope>runtime</scope></dependency>
<dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-jackson</artifactId><version>0.12.6</version><scope>runtime</scope></dependency>
</dependencies>
</project>
```

```yaml
# task-service/src/main/resources/application.yml
server:
  port: 8082
spring:
  datasource:
    url: ${DB_URL:jdbc:postgresql://localhost:5432/taskdb}
    username: ${DB_USER:postgres}
    password: ${DB_PASS:postgres}
  jpa:
    hibernate:
      ddl-auto: update
```

```java
// TaskServiceApplication.java
package com.tasks.tasks;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication
public class TaskServiceApplication {
  public static void main(String[] args) { SpringApplication.run(TaskServiceApplication.class, args); }
}
```

```java
// Task.java
package com.tasks.tasks;
import jakarta.persistence.*;
import java.time.Instant;
@Entity @Table(name = "tasks")
public class Task {
  @Id @GeneratedValue(strategy = GenerationType.IDENTITY) public Long id;
  @Column(nullable = false) public String owner;
  @Column(nullable = false) public String title;
  @Column(nullable = false) public boolean done = false;
  @Column(name = "created_at", nullable = false) public Instant createdAt = Instant.now();
}
```

```java
// TaskRepository.java
package com.tasks.tasks;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
public interface TaskRepository extends JpaRepository<Task, Long> {
  Page<Task> findByOwner(String owner, Pageable p);
  Optional<Task> findByIdAndOwner(Long id, String owner);
}
```

- [ ] **Step 2: Write JWT filter + security**

```java
// JwtAuthFilter.java
package com.tasks.tasks;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
@Component
public class JwtAuthFilter extends OncePerRequestFilter {
  private final javax.crypto.SecretKey key;
  public JwtAuthFilter(@Value("${JWT_SECRET:change-me-to-32-chars-minimum-secret!!}") String secret) {
    this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
  }
  @Override
  protected boolean shouldNotFilter(HttpServletRequest r) {
    return r.getRequestURI().equals("/api/health");
  }
  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
    String h = req.getHeader("Authorization");
    if (h == null || !h.startsWith("Bearer ")) { res.setStatus(401); return; }
    try {
      String user = Jwts.parser().verifyWith(key).build()
        .parseSignedClaims(h.substring(7)).getPayload().getSubject();
      SecurityContextHolder.getContext().setAuthentication(
        new UsernamePasswordAuthenticationToken(user, null, List.of()));
      chain.doFilter(req, res);
    } catch (Exception e) { res.setStatus(401); }
  }
}
```

```java
// SecurityConfig.java (task-service)
package com.tasks.tasks;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
@Configuration
public class SecurityConfig {
  private final JwtAuthFilter jwt;
  public SecurityConfig(JwtAuthFilter j) { jwt = j; }
  @Bean SecurityFilterChain chain(HttpSecurity h) throws Exception {
    return h.csrf(c -> c.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .authorizeHttpRequests(a -> a.requestMatchers("/api/health").permitAll().anyRequest().authenticated())
      .addFilterBefore(jwt, UsernamePasswordAuthenticationFilter.class).build();
  }
}
```

- [ ] **Step 3: Write TaskController**

```java
// TaskController.java
package com.tasks.tasks;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.domain.*;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.util.Map;
@RestController @RequestMapping("/api")
public class TaskController {
  public record CreateReq(@NotBlank String title) {}
  public record UpdateReq(@NotBlank String title, boolean done) {}
  private final TaskRepository repo;
  public TaskController(TaskRepository r) { repo = r; }
  @GetMapping("/health") public Map<?, ?> health() { return Map.of("status", "UP"); }
  @GetMapping("/tasks")
  public Map<?, ?> list(Authentication auth,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size) {
    // ponytail: fixed sort createdAt desc, add sort param if users ask
    Page<Task> p = repo.findByOwner(auth.getName(), PageRequest.of(page, Math.min(size, 50), Sort.by("createdAt").descending()));
    return Map.of("content", p.getContent(), "page", p.getNumber(), "size", p.getSize(),
      "totalElements", p.getTotalElements(), "totalPages", p.getTotalPages());
  }
  @PostMapping("/tasks")
  public ResponseEntity<Task> create(Authentication auth, @Valid @RequestBody CreateReq r) {
    Task t = new Task(); t.owner = auth.getName(); t.title = r.title();
    return ResponseEntity.status(201).body(repo.save(t));
  }
  @PutMapping("/tasks/{id}")
  public Task update(Authentication auth, @PathVariable Long id, @Valid @RequestBody UpdateReq r) {
    Task t = repo.findByIdAndOwner(id, auth.getName())
      .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "not found"));
    t.title = r.title(); t.done = r.done();
    return repo.save(t);
  }
  @DeleteMapping("/tasks/{id}")
  public Map<?, ?> delete(Authentication auth, @PathVariable Long id) {
    Task t = repo.findByIdAndOwner(id, auth.getName())
      .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "not found"));
    repo.delete(t); return Map.of("ok", true);
  }
  @RestControllerAdvice
  static class Advice {
    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<?> handle(ResponseStatusException e) {
      return ResponseEntity.status(e.getStatusCode()).body(Map.of("message", e.getReason()));
    }
  }
}
```

```dockerfile
# task-service/Dockerfile
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY target/task-service-0.1.0.jar app.jar
ENTRYPOINT ["java","-jar","app.jar"]
```

- [ ] **Step 4: Verify + commit**

Run: `mvn -pl task-service package -DskipTests`
Expected: jar builds.
Run: `TOKEN=<access-from-Task1-login>; curl -s localhost:8082/api/tasks?page=0"&"size=10 -H "Authorization: Bearer $TOKEN"; echo; curl -s -X POST localhost:8082/api/tasks -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"title\":\"first\"}"; echo`
Expected: paged JSON then 201 task.

```bash
git add task-service
git commit -m "feat: add task-service with paged CRUD"
```

### Task 3: web (React Vite)

**Files:**
- Create: `web/package.json`
- Create: `web/vite.config.js`
- Create: `web/.env`
- Create: `web/index.html`
- Create: `web/src/main.jsx`
- Create: `web/src/api.js`
- Create: `web/src/App.jsx`
- Create: `web/nginx.conf`
- Create: `web/Dockerfile`

**Interfaces:**
- Consumes: Task 1 + Task 2 endpoints, `VITE_AUTH_URL`, `VITE_TASK_URL`.
- Produces: SPA on :3000.

- [ ] **Step 1: Write scaffold + api.js**

```json
// web/package.json
{"name":"web","private":true,"type":"module","scripts":{"dev":"vite","build":"vite build"},"dependencies":{"react":"^18.3.1","react-dom":"^18.3.1"},"devDependencies":{"vite":"^5.4.0","@vitejs/plugin-react":"^4.3.0"}}
```

```js
// web/vite.config.js
import react from "@vitejs/plugin-react";
export default { plugins: [react()], server: { port: 5173 } };
```

```
# web/.env
VITE_AUTH_URL=http://localhost:8081/api/auth
VITE_TASK_URL=http://localhost:8082/api
```

```html
<!-- web/index.html -->
<!doctype html><html><body><div id="root"></div><script type="module" src="/src/main.jsx"></script></body></html>
```

```jsx
// web/src/main.jsx
import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
createRoot(document.getElementById("root")).render(<App />);
```

```js
// web/src/api.js
const AUTH = import.meta.env.VITE_AUTH_URL;
const TASKS = import.meta.env.VITE_TASK_URL;
const get = (k) => localStorage.getItem(k);
let refreshing = null;
async function refresh() {
  if (!refreshing) {
    refreshing = fetch(`${AUTH}/refresh`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: get("refreshToken") }),
    }).then(async (r) => {
      if (!r.ok) throw new Error("refresh failed");
      const j = await r.json();
      localStorage.setItem("accessToken", j.accessToken);
      localStorage.setItem("refreshToken", j.refreshToken);
      refreshing = null; return j.accessToken;
    }).catch((e) => { refreshing = null; throw e; });
  }
  return refreshing;
}
export async function authed(path, opts = {}, retry = true) {
  const r = await fetch(`${TASKS}${path}`, {
    ...opts,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${get("accessToken")}`, ...(opts.headers || {}) },
  });
  if (r.status === 401 && retry) { await refresh(); return authed(path, opts, false); }
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
export const authApi = {
  register: (b) => fetch(`${AUTH}/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) }).then(async (r) => { if (!r.ok) throw new Error(await r.text()); return r.json(); }),
  login: (b) => fetch(`${AUTH}/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) }).then(async (r) => { if (!r.ok) throw new Error(await r.text()); return r.json(); }),
};
export const taskApi = {
  list: (page = 0, size = 10) => authed(`/tasks?page=${page}&size=${size}`),
  create: (title) => authed("/tasks", { method: "POST", body: JSON.stringify({ title }) }),
  update: (id, body) => authed(`/tasks/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  remove: (id) => authed(`/tasks/${id}`, { method: "DELETE" }),
};
```

- [ ] **Step 2: Write App.jsx**

```jsx
// web/src/App.jsx
import { useEffect, useState } from "react";
import { authApi, taskApi } from "./api.js";
export default function App() {
  const [user, setUser] = useState(localStorage.getItem("username") || "");
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ username: "", password: "" });
  const [err, setErr] = useState("");
  const [tasks, setTasks] = useState([]);
  const [page, setPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [title, setTitle] = useState("");
  const logged = !!localStorage.getItem("accessToken");
  async function load(p = page) {
    try { const j = await taskApi.list(p, 10); setTasks(j.content); setTotalPages(j.totalPages); setPage(j.page); }
    catch (e) { if (String(e.message).includes("refresh failed")) logout(); else setErr(e.message); }
  }
  useEffect(() => { if (logged) load(0); }, []);
  async function submit(e) {
    e.preventDefault(); setErr("");
    try {
      const fn = mode === "login" ? authApi.login : authApi.register;
      const j = await fn(form);
      if (mode === "register") { setMode("login"); setForm({ username: form.username, password: "" }); return; }
      localStorage.setItem("accessToken", j.accessToken);
      localStorage.setItem("refreshToken", j.refreshToken);
      localStorage.setItem("username", j.username);
      setUser(j.username); load(0);
    } catch (e) { setErr(e.message); }
  }
  function logout() { localStorage.clear(); setUser(""); setTasks([]); }
  if (!logged) return (
    <main style={{ maxWidth: 360, margin: "40px auto", fontFamily: "system-ui" }}>
      <h1>Tasks</h1>
      <button onClick={() => setMode(mode === "login" ? "register" : "login")}>{mode === "login" ? "go register" : "go login"}</button>
      <form onSubmit={submit}><input placeholder="user" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /><input type="password" placeholder="pass" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /><button>{mode}</button></form>
      {err && <p>{err}</p>}
    </main>
  );
  return (
    <main style={{ maxWidth: 560, margin: "40px auto", fontFamily: "system-ui" }}>
      <h1>{user}'s tasks</h1><button onClick={logout}>logout</button>
      <form onSubmit={async (e) => { e.preventDefault(); await taskApi.create(title); setTitle(""); load(page); }}><input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="new task" /><button>add</button></form>
      {err && <p>{err}</p>}
      <ul>{tasks.map((t) => (
        <li key={t.id}><input type="checkbox" checked={t.done} onChange={async () => { await taskApi.update(t.id, { title: t.title, done: !t.done }); load(page); }} />{t.title}<button onClick={async () => { if (confirm("delete?")) { await taskApi.remove(t.id); load(page); } }}>x</button></li>
      ))}</ul>
      <div><button disabled={page <= 0} onClick={() => load(page - 1)}>prev</button><span> {page + 1}/{Math.max(totalPages, 1)} </span><button disabled={page + 1 >= totalPages} onClick={() => load(page + 1)}>next</button></div>
    </main>
  );
}
```

```
# web/nginx.conf
server { listen 80; root /usr/share/nginx/html; location / { try_files $uri /index.html; } }
```

```dockerfile
# web/Dockerfile
FROM node:20-alpine AS b
WORKDIR /w
COPY package.json ./
RUN npm install
COPY . ./
RUN npm run build
FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=b /w/dist /usr/share/nginx/html
```

- [ ] **Step 3: Verify + commit**

Run: `npm --prefix web install; npm --prefix web run build`
Expected: `web/dist` created, no errors.

```bash
git add web
git commit -m "feat: add React web with refresh and paging"
```

### Task 4: compose + run

**Files:**
- Create: `db/init.sql`
- Create: `docker-compose.yml`
- Create: `README.md`

**Interfaces:**
- Consumes: Task 1-3 images.
- Produces: `docker compose up` system.

- [ ] **Step 1: Write compose + init + README**

```sql
-- db/init.sql
SELECT 'CREATE DATABASE authdb' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'authdb')\gexec
SELECT 'CREATE DATABASE taskdb' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'taskdb')\gexec
```

```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: postgres
    ports: ["5432:5432"]
    volumes: ["pgdata:/var/lib/postgresql/data", "./db/init.sql:/docker-entrypoint-initdb.d/init.sql"]
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U postgres"], interval: 5s, retries: 10 }
  auth-service:
    build: ./auth-service
    ports: ["8081:8081"]
    environment:
      DB_URL: jdbc:postgresql://postgres:5432/authdb
      DB_USER: postgres
      DB_PASS: postgres
      JWT_SECRET: ${JWT_SECRET:-change-me-to-32-chars-minimum-secret!!}
    depends_on: { postgres: { condition: service_healthy } }
  task-service:
    build: ./task-service
    ports: ["8082:8082"]
    environment:
      DB_URL: jdbc:postgresql://postgres:5432/taskdb
      DB_USER: postgres
      DB_PASS: postgres
      JWT_SECRET: ${JWT_SECRET:-change-me-to-32-chars-minimum-secret!!}
    depends_on: { postgres: { condition: service_healthy } }
  web:
    build: ./web
    ports: ["3000:80"]
volumes: { pgdata: {} }
```

```md
<!-- README.md -->
# Task Manager MVP
`JWT_SECRET=<32+chars> docker compose up --build` -> web http://localhost:3000
Dev: run pg via compose, `./mvnw spring-boot:run` in each service, `npm run dev` in web.
Smoke: register -> login -> `GET /api/tasks?page=0&size=10` -> CRUD in UI, refresh on 401 auto.
```

- [ ] **Step 2: Verify full system + commit + push**

Run: `JWT_SECRET=test-secret-min-32-chars-1234567890 docker compose up --build -d; sleep 20; docker compose ps`
Expected: 4 containers Up.
Run: `curl -s -X POST localhost:8081/api/auth/register -H "Content-Type: application/json" -d "{\"username\":\"e2e\",\"password\":\"pass1234\"}"; echo; L=$(curl -s -X POST localhost:8081/api/auth/login -H "Content-Type: application/json" -d "{\"username\":\"e2e\",\"password\":\"pass1234\"}"); echo "$L" | head -c 120; echo; A=$(echo "$L" | python3 -c "import sys,json;print(json.load(sys.stdin)['accessToken'])"); R=$(echo "$L" | python3 -c "import sys,json;print(json.load(sys.stdin)['refreshToken'])"); curl -s "localhost:8082/api/tasks?page=0&size=10" -H "Authorization: Bearer $A"; echo; curl -s -X POST localhost:8081/api/auth/refresh -H "Content-Type: application/json" -d "{\"refreshToken\":\"$R\"}" | head -c 120; echo`
Expected: register 201/409, login tokens, paged `{"content":[]}`, refresh new pair.
Run: `docker compose down`
Expected: clean stop.

```bash
git add docker-compose.yml db/init.sql README.md
git commit -m "feat: add compose and run docs"
git push origin master
```

## Self-Review

- Spec coverage: register/login/refresh/logout in Task 1, paged owner-scoped CRUD + health in Task 2, SPA login/register/pager/auto-refresh in Task 3, compose + smoke in Task 4. All covered.
- Placeholder scan: no TBD/TODO, all code blocks concrete, error messages explicit.
- Type consistency: `accessToken/refreshToken/username` names match Java `issue()` and `api.js`; `/api/auth/*` + `/api/tasks?page&size` match controllers and frontend; `JWT_SECRET` + `DB_URL` env match yml + compose.
