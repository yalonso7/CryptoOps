import { z } from 'zod';

const envSchema = z.object({
  NEXT_PUBLIC_INFURA_ID: z.string().min(1),
  NEXT_PUBLIC_ALCHEMY_ID: z.string().min(1),
  NEXT_PUBLIC_WALLET_CONNECT_ID: z.string().min(1),
  API_SECRET_KEY: z.string().min(32),
  JWT_SECRET: z.string().min(32),
});

export const env = envSchema.parse({
  NEXT_PUBLIC_INFURA_ID: process.env.NEXT_PUBLIC_INFURA_ID,
  NEXT_PUBLIC_ALCHEMY_ID: process.env.NEXT_PUBLIC_ALCHEMY_ID,
  NEXT_PUBLIC_WALLET_CONNECT_ID: process.env.NEXT_PUBLIC_WALLET_CONNECT_ID,
  API_SECRET_KEY: process.env.API_SECRET_KEY,
  JWT_SECRET: process.env.JWT_SECRET,
});