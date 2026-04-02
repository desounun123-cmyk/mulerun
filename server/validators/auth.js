/**
 * server/validators/auth.js
 *
 * Zod schemas for all authentication endpoints:
 *   POST /api/auth/register
 *   POST /api/auth/login
 *   POST /api/auth/forgot
 *   POST /api/auth/reset
 *   PUT  /api/auth/password
 *   GET  /api/auth/verify
 *   POST /api/auth/totp/verify
 *   POST /api/auth/totp/disable
 */
'use strict';

const { z, email, password, passwordRequired, userName, totpCode } = require('./primitives');

const register = z.object({
  name: userName,
  email: email,
  password: password,
  captchaAnswer: z.union([z.number(), z.string()]).optional().nullable(),
});

const login = z.object({
  email: z.string().min(1, 'Email is required.'),
  password: z.string().min(1, 'Password is required.'),
  rememberMe: z.boolean().optional(),
  captchaAnswer: z.union([z.number(), z.string()]).optional().nullable(),
  totpToken: z.string().optional(),
});

const forgotPassword = z.object({
  email: z.string().min(1, 'Email is required.'),
});

const resetPassword = z.object({
  token: z.string().min(1, 'Token is required.'),
  newPassword: password,
});

const changePassword = z.object({
  currentPassword: z.string().min(1, 'Current password is required.'),
  newPassword: password,
});

const verifyToken = z.object({
  token: z.string().min(1, 'Verification token is required.'),
});

const totpVerify = z.object({
  token: totpCode,
});

const totpDisable = z.object({
  password: z.string().min(1, 'Password is required to disable 2FA.'),
});

module.exports = {
  register,
  login,
  forgotPassword,
  resetPassword,
  changePassword,
  verifyToken,
  totpVerify,
  totpDisable,
};
