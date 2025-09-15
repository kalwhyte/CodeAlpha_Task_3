# Secure Coding Review – Node.js/Express REST API (TASK 3)

**Student:** Whyte Emmanuel  
**Date:** 16 Aug 2025  
**Application Chosen:** Node.js/Express REST API (with MongoDB and JWT Authentication)

---

## 1) Executive Summary
For this secure coding review, I assessed a simple Node.js/Express REST API that handles users, orders, and file uploads.  
The review was carried out through **manual inspection** and the use of **static analysis tools**.  

Several vulnerabilities were identified:
- Weak input validation  
- Insecure authentication/authorization  
- Unsafe file upload handling  
- Missing security headers  

I provide fixes and best practices for each issue, as well as a prioritized remediation plan.

---

## 2) Methodology

**Approach:**
- Manual code inspection (input validation, authentication, authorization, error handling, file upload handling).
- Static analysis with:
  - `npm audit` (dependency issues)
  - `eslint-plugin-security` (unsafe coding patterns)
  - `semgrep` (OWASP Top 10 ruleset)

**Scope:**
- Node.js/Express backend with JWT authentication and MongoDB.  
- Excluded frontend or infrastructure review.

---

## 3) Findings

### 🔴 High-Risk Issues

#### 1. NoSQL Injection
User input (`req.query`) passed directly into MongoDB queries without sanitization.  

**Vulnerable Code:**
```js
// ❌ Vulnerable
const user = await User.findOne({ username: req.query.username });
````

**Fix:**

```js
// ✅ Fixed
const { body, validationResult } = require("express-validator");
const mongoSanitize = require("express-mongo-sanitize");

app.use(mongoSanitize());

app.get("/user",
  body("username").isAlphanumeric().trim(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const user = await User.findOne({ username: req.body.username });
    res.json(user);
  }
);
```

---

#### 2. IDOR (Insecure Direct Object Reference)

Users could fetch other users’ orders by guessing IDs.

**Vulnerable Code:**

```js
// ❌ Anyone can access any order
const order = await Order.findById(req.params.id);
```

**Fix:**

```js
// ✅ Ensure ownership
const order = await Order.findOne({ 
  _id: req.params.id, 
  user: req.user.id 
});
```

---

#### 3. Weak JWT Handling

Hardcoded secret, long expiry, no refresh token rotation.

**Vulnerable Code:**

```js
// ❌ Insecure
jwt.sign(payload, "secret123", { expiresIn: "7d" });
```

**Fix:**

```js
// ✅ Secure
require("dotenv").config();

jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "15m" });

// Refresh token rotation example
const refreshToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
```

---

#### 4. Insecure File Uploads

Multer allowed any file type with `originalname`, no size limit.

**Vulnerable Code:**

```js
// ❌ Insecure
const upload = multer({ dest: "uploads/" });
```

**Fix:**

```js
// ✅ Secure
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "application/pdf"];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Invalid file type"), false);
    }
    cb(null, true);
  },
});
```

---

### 🟠 Medium-Risk Issues

#### 1. Missing Security Headers

No `helmet`, CSP, or HSTS enabled.

**Fix:**

```js
const helmet = require("helmet");
app.use(helmet());
```

---

#### 2. Overly Permissive CORS

```js
// ❌ Insecure
app.use(cors());
```

**Fix:**

```js
// ✅ Restrict origins
app.use(cors({
  origin: ["https://trusted-domain.com"],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));
```

---

#### 3. No Rate Limiting

```js
// ❌ No protection
```

**Fix:**

```js
// ✅ Add rate limiting
const rateLimit = require("express-rate-limit");

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts. Please try again later."
});

app.use("/api/auth", authLimiter);
```

---

### 🟢 Low-Risk Issues

#### 1. Error Messages Leak Details

```js
// ❌ Insecure
res.status(500).json({ error: err.message });
```

**Fix:**

```js
// ✅ Secure
res.status(500).json({ error: "Internal server error" });
```

---

#### 2. Secrets in Code

```js
// ❌ Insecure
const jwtSecret = "secret123";
```

**Fix:**

```js
// ✅ Secure
require("dotenv").config();
const jwtSecret = process.env.JWT_SECRET;
```

---

#### 3. Dependency Risks

No automated dependency updates.

**Fix:**

```bash
npm audit fix
```

Use **Dependabot**, **Snyk**, or **GitHub Security Alerts**.

---

## 4) Recommendations

* Validate and sanitize all inputs.
* Enforce strict authentication and authorization checks.
* Secure JWT handling with strong secrets and refresh token rotation.
* Lock down file uploads with strict filters and safe storage.
* Use `helmet` for headers and enable HTTPS.
* Restrict CORS to trusted origins.
* Implement rate limiting and centralized error-handling.
* Store secrets securely and automate dependency scanning.

---

## 5) Remediation Plan

**Week 1 (High Priority):**

* Add input validation & sanitization.
* Enforce authorization on all resource access.
* Improve JWT handling and secret storage.
* Secure file upload handling.

**Week 2 (Medium Priority):**

* Add helmet, CSP, HSTS.
* Restrict CORS settings.
* Add rate limiting.

**Week 3 (Low Priority/Ongoing):**

* Centralize error handling.
* Store secrets securely.
* Automate dependency scanning.

---

## 6) Conclusion

The reviewed Node.js/Express REST API shows several common vulnerabilities that can be exploited if not addressed.
By applying the recommended fixes, following secure coding best practices, and using continuous security tooling, the application can be hardened against most common attacks.

```

---
