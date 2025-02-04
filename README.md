# Authentication System with Single Sign-On (SSO)

## Overview

This project implements a **centralized authentication system** with **Single Sign-On (SSO)** for multiple applications. The system is built using **Node.js, Express.js, MongoDB, and JWT**, with additional support for email verification, password resets, and two-factor authentication (2FA) using **NodeMailer**.

### **Key Features**

- **User Authentication**: Registration, login, and token-based authentication.
- **Single Sign-On (SSO)**: Authenticate once and access multiple websites.
- **Email Verification**: Users must verify their email before accessing services.
- **Forgot Password / Password Reset**: Secure recovery of forgotten passwords.
- **Two-Factor Authentication (2FA)**: OTP-based authentication via email.
- **CRUD Operations for Users & Admins**:
  - Users/Admins can **update** their profiles.
  - Users/Admins can **delete** their accounts.
  - Users/Admins can **view** their own details.
- **Admin System**:
  - Admins have **role-based access control**.
  - Permissions can be **granularly assigned** (e.g., user management, content control).
  - Admins can **promote/demote** other admins.
- **Security Enhancements**:
  - Passwords are securely **hashed** before storage.
  - **Rate-limiting** is applied to prevent brute-force attacks.
  - **Session tracking** with IP, location, and login timestamps.
- **NodeMailer Integration**:
  - Styled email templates for **verification, password reset, and 2FA**.
  - SMTP authentication using Google Workspace.

## **Technologies Used**

- **Backend**: Node.js, Express.js
- **Database**: MongoDB (Mongoose ODM)
- **Authentication**: JWT (JSON Web Tokens), bcrypt.js for password hashing
- **Email Service**: NodeMailer with Google SMTP
- **Frontend**: Not included (SSO-ready for integration)

---

## **1. File Structure**

```
project-root/
├── src/
│   ├── config/
│   │   ├── db.js  # Database connection setup
│   ├── controllers/
│   │   ├── authController.js  # User authentication logic
│   │   ├── adminController.js  # Admin-specific logic
│   │   ├── userController.js  # User management logic
│   │   ├── emailController.js  # Handles sending emails
│   ├── middlewares/
│   │   ├── authMiddleware.js  # Protects routes
│   │   ├── rateLimiter.js  # Limits request rate
│   ├── models/
│   │   ├── User.js  # User schema
│   │   ├── Admin.js  # Admin schema
│   ├── routes/
│   │   ├── authRoutes.js  # Routes for authentication
│   │   ├── userRoutes.js  # User profile management
│   │   ├── adminRoutes.js  # Admin-specific operations
│   ├── services/
│   │   ├── emailService.js  # Handles email sending
│   ├── utils/
│   │   ├── helpers.js  # Utility functions
├── .env  # Environment variables
├── index.js  # Server entry point
├── package.json  # Dependencies
├── README.md  # Documentation
```

---

## **2. API Endpoints**

### **Authentication (SSO)**

#### Register User

- **Endpoint:** `POST /api/v1/auth/register`
- **Request Body:**

  ```json
  {
    "name": "John Doe",
    "email": "john.doe@example.com",
    "password": "SecurePassword123",
    "confirmPassword": "SecurePassword123"
  }
  ```

#### Login User

- **Endpoint:** `POST /api/v1/auth/login`
- **Request Body:**

  ```json
  {
    "email": "john.doe@example.com",
    "password": "SecurePassword123"
  }
  ```

#### Validate JWT Token

- **Endpoint:** `GET /api/v1/auth/validate-token`
- **Headers:** `Authorization: Bearer JWT_TOKEN`

#### Logout User

- **Endpoint:** `POST /api/v1/auth/logout`

---

### **Email Verification & Password Recovery**

#### Verify Email

- **Endpoint:** `GET /api/v1/auth/verify-email?token=TOKEN`

#### Resend Verification Email

- **Endpoint:** `POST /api/v1/auth/resend-verification`
- **Request Body:**

  ```json
  {
    "email": "john.doe@example.com"
  }
  ```

#### Forgot Password

- **Endpoint:** `POST /api/v1/auth/forgot-password`
- **Request Body:**

  ```json
  {
    "email": "john.doe@example.com"
  }
  ```

#### Reset Password

- **Endpoint:** `POST /api/v1/auth/reset-password`
- **Request Body:**

  ```json
  {
    "token": "RESET_TOKEN",
    "newPassword": "NewPassword123",
    "confirmPassword": "NewPassword123"
  }
  ```

---

### **Two-Factor Authentication (2FA)**

#### Send OTP

- **Endpoint:** `POST /api/v1/auth/send-otp`
- **Request Body:**

  ```json
  {
    "email": "john.doe@example.com"
  }
  ```

#### Verify OTP

- **Endpoint:** `POST /api/v1/auth/verify-otp`
- **Request Body:**

  ```json
  {
    "email": "john.doe@example.com",
    "otp": "123456"
  }
  ```

---

### **CRUD Operations for Users & Admins**

#### Get User Profile

- **Endpoint:** `GET /api/v1/auth/profile`

#### Update User Profile

- **Endpoint:** `PUT /api/v1/auth/update-profile`
- **Request Body:**

  ```json
  {
    "name": "New Name",
    "password": "NewPassword123"
  }
  ```

#### Delete User Account

- **Endpoint:** `DELETE /api/v1/auth/delete-account`

#### Similar endpoints exist for Admins under `/api/v1/admin/...`

---

## **3. Running the Project**

### **1. Clone the Repository**

```sh
git clone https://github.com/your-repo.git
cd sso-auth-server
```

### **2. Install Dependencies**

```sh
npm install
```

### **3. Set Up Environment Variables**

Create a `.env` file and add:

```
PORT=4000
MONGO_URI=your_mongo_connection_string
JWT_SECRET=your_jwt_secret
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
```

### **4. Start the Server**

```sh
npm start
```

---

## **4. Future Improvements**

- **OAuth Support** (Google, GitHub, Facebook authentication)
- **SMS-Based Two-Factor Authentication (Twilio)**
- **Session Management for Logged-in Users**
- **Logging & Monitoring (Winston, Loggly, Datadog)**

---

## **5. License**

MIT License

---

This README provides a full overview of the authentication system, API endpoints, and project setup.
