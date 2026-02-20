# Standardized Error Handling & API Responses

## 🚀 Overview
Issue #712 introduces a centralized data architecture for handling errors and standardizing API responses. It moves the application away from ad-hoc `res.send` calls and inconsistent error structures towards a **JSend-compliant** communication protocol.

## 🏗️ Core Components

### 1. The AppError Class (`utils/AppError.js`)
All known operational errors (validation failures, missing resources, etc.) MUST be wrapped in the `AppError` class.
- **Operational Errors**: Errors we can anticipate and handle gracefully.
- **Programmer Errors**: Unexpected bugs or crashes (these are treated as 500s and log full stack traces internally).

### 2. Standardized Response Factory (`utils/ResponseFactory.js`)
The `ResponseFactory` is the ONLY way to send data back to the client. It ensures every response has a predictable shape:
- **Success (`status: "success"`)**: For successful operations. Includes `data` and optional `message`.
- **Fail (`status: "fail"`)**: For client errors (4xx). Includes `data` (usually specific field errors).
- **Error (`status: "error"`)**: For server errors (5xx). Includes `message` (and `stack` in development).

### 3. Global Error Middleware (`middleware/globalErrorHandler.js`)
This is the single hub for error processing. It intercepts all errors and:
- **Normalizes DB Errors**: Automatically converts Mongoose `CastError`, `ValidationError`, and duplicate key errors into user-friendly `AppError` messages.
- **Normalizes Security Errors**: Handles JWT expiration and invalidation.
- **Sanitizes Production Output**: Ensures that stack traces and sensitive internal error messages are NEVER leaked to the end user in production.

## 🛠️ Usage Patterns

### Throwing an error in a route
```javascript
router.get('/:id', async (req, res, next) => {
    const item = await Model.findById(req.params.id);
    if (!item) {
        return next(new AppError('No document found with that ID', 404));
    }
    ResponseFactory.success(res, item);
});
```

### Formatting success responses
```javascript
ResponseFactory.success(res, { user }, 201, 'User registered successfully');
```

## ✅ Implementation Checklist
- [x] Custom `AppError` class with operational flagging.
- [x] JSend-compliant `ResponseFactory`.
- [x] Centralized error middleware with environment-based logic.
- [x] Mongoose/MongoDB error normalization.
- [x] Sanitized production error responses.
- [x] Logic for shielding internal stack traces.

## 🧪 Testing
Run the error handling test suite:
```bash
npx mocha tests/errorHandling.test.js
```
