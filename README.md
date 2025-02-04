# SSO Authentication Service

```bash
project-root/
├── src/
│   ├── config/
│   │   └── db.js             # Database connection setup and configuration (MongoDB)
│   ├── controllers/
│   │   └── authController.js # Functions handling registration, login, token validation, and logout
│   ├── middlewares/
│   │   ├── authMiddleware.js # Middleware to protect routes by validating JWT tokens
│   │   └── rateLimiter.js    # Middleware for rate limiting (e.g., on login endpoints)
│   ├── models/
│   │   └── User.js           # Mongoose schema and model for user data
│   ├── routes/
│   │   └── authRoutes.js     # Express routes for authentication (e.g., /register, /login, /logout, /validate-token)
│   ├── services/
│   │   └── tokenService.js   # Functions for generating and verifying JWT tokens
│   ├── utils/
│   │   └── helpers.js        # Utility functions (e.g., for formatting responses or error handling)
├── .env                      # Environment variables (e.g., DB connection string, JWT secret)
├── index.js                  # Entry point for the application (configured as an ES Module)
├── package.json              # Project dependencies and scripts
```
