import { NextApiRequest, NextApiResponse } from 'next';
import rateLimit from 'express-rate-limit';
import { verify } from 'jsonwebtoken';
import { env } from '../config/env';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

export function apiSecurityMiddleware(
  req: NextApiRequest,
  res: NextApiResponse,
  next: () => void
) {
  // CORS protection
  res.setHeader('Access-Control-Allow-Origin', process.env.NEXT_PUBLIC_APP_URL || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  
  // API key validation
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== env.API_SECRET_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Apply rate limiting
  limiter(req, res, next);
}