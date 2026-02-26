// functions/api/auth/[[path]].ts
import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

const subjects = createSubjects({
  user: object({
    id: string(),
  }),
});

// PAGES FUNCTIONS handler -代替 fetch
export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // Handle root redirect
  if (url.pathname === "/api/auth" || url.pathname === "/api/auth/") {
    const authUrl = new URL(request.url);
    authUrl.pathname = "/api/auth/authorize";
    authUrl.searchParams.set("client_id", "readtalk-client");
    authUrl.searchParams.set("redirect_uri", "https://readtalk.pages.dev/account");
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("scope", "openid");
    return Response.redirect(authUrl.toString(), 302);
  }

  // Buat request object yang pathnya disesuaikan
  const newUrl = new URL(request.url);
  // Hapus /api/auth dari path karena issuer expects /authorize, /token, dll
  newUrl.pathname = newUrl.pathname.replace(/^\/api\/auth/, '');
  
  const newRequest = new Request(newUrl.toString(), {
    method: request.method,
    headers: request.headers,
    body: request.body,
  });

  // Panggil issuer dengan format Pages Functions
  try {
    const response = await issuer({
      storage: CloudflareStorage({
        namespace: env.AUTH_STORAGE,
      }),
      subjects,
      providers: {
        password: PasswordProvider(
          PasswordUI({
            sendCode: async (email, code) => {
              console.log(`[OpenAuth] Sending code ${code} to ${email}`);
              // Di production: kirim email
            },
            copy: {
              input_code: "Masukkan kode (cek log Worker atau console)",
            },
          }),
        ),
      },
      theme: {
        title: "READTalk Login",
        primary: "#ff0000",
        favicon: "https://workers.cloudflare.com/favicon.ico",
        logo: {
          dark: "https://imagedelivery.net/.../logo-dark",
          light: "https://imagedelivery.net/.../logo-light",
        },
      },
      success: async (ctx, value) => {
        const userId = await getOrCreateUser(env, value.email);
        console.log(`User authenticated: ${userId} (${value.email})`);
        return ctx.subject("user", { id: userId });
      },
    }).fetch(newRequest, env, context);

    return response;
    
  } catch (error) {
    console.error("Auth error:", error);
    return new Response(JSON.stringify({ error: "Authentication failed" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// Fungsi getOrCreateUser (sama persis)
async function getOrCreateUser(env: Env, email: string): Promise<string> {
  const result = await env.AUTH_DB.prepare(`
    INSERT INTO user (email)
    VALUES (?)
    ON CONFLICT (email) DO UPDATE SET email = email
    RETURNING id;
  `).bind(email).first<{ id: string }>();
  
  if (!result) {
    throw new Error(`Unable to process user: ${email}`);
  }
  console.log(`Found or created user ${result.id} with email ${email}`);
  return result.id;
}

// Type Env untuk Pages Functions
interface Env {
  AUTH_STORAGE: KVNamespace;
  AUTH_DB: D1Database;
}
