import { z } from "zod";

export const AuthUser = z.object({
  id: z.string(),
  email: z.string().nullable().optional(),
  firstName: z.string().nullable().optional(),
  lastName: z.string().nullable().optional(),
  profileImageUrl: z.string().nullable().optional(),
  role: z.string().optional(),
});

export type AuthUser = z.infer<typeof AuthUser>;

export const GetCurrentAuthUserResponse = z.object({
  user: AuthUser.nullable(),
});

export const ExchangeMobileAuthorizationCodeBody = z.object({
  code: z.string(),
  code_verifier: z.string(),
  redirect_uri: z.string(),
  state: z.string(),
  nonce: z.string().optional(),
});

export const ExchangeMobileAuthorizationCodeResponse = z.object({
  token: z.string(),
});

export const LogoutMobileSessionResponse = z.object({
  success: z.boolean(),
});
