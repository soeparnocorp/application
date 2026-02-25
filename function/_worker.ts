// function/_worker.ts

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

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // Optional: Redirect root ke authorize kalau user akses langsung
    if (url.pathname === "/") {
      url.pathname = "/authorize";
      url.searchParams.set("client_id", "readtalk-client");  // ganti dengan client_id real kamu
      url.searchParams.set("redirect_uri", "https://readtalk.pages.dev/account");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", "openid");
      return Response.redirect(url.toString(), 302);
    }

    // Kode OpenAuth utama (ini yang handle /authorize, /token, /password/*, dll)
    return issuer({
      storage: CloudflareStorage({
        namespace: env.AUTH_STORAGE,  // KV binding WAJIB di-set di dashboard
      }),
      subjects,
      providers: {
        password: PasswordProvider(
          PasswordUI({
            sendCode: async (email, code) => {
              console.log(`[OpenAuth] Sending code ${code} to ${email}`);
              // Di production: kirim email real via Resend/SendGrid binding
            },
            copy: {
              input_code: "Masukkan kode (cek log Worker atau console)",
            },
          }),
        ),
      },
      theme: {
        title: "READTalk Login",
        primary: "#ff0000",  // atau warna brand kamu
        favicon: "https://workers.cloudflare.com/favicon.ico",
        logo: {
          dark: "https://imagedelivery.net/.../logo-dark",  // update kalau punya
          light: "https://imagedelivery.net/.../logo-light",
        },
      },
      success: async (ctx, value) => {
        const userId = await getOrCreateUser(env, value.email);
        console.log(`User authenticated: ${userId} (${value.email})`);
        return ctx.subject("user", { id: userId });
      },
    }).fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;

// Fungsi getOrCreateUser (copy dari kode asli kamu)
async function getOrCreateUser(env: Env, email: string): Promise<string> {
  const result = await env.AUTH_DB.prepare(
    `
    INSERT INTO user (email)
    VALUES (?)
    ON CONFLICT (email) DO UPDATE SET email = email
    RETURNING id;
    `
  )
    .bind(email)
    .first<{ id: string }>();
  if (!result) {
    throw new Error(`Unable to process user: ${email}`);
  }
  console.log(`Found or created user ${result.id} with email ${email}`);
  return result.id;
}
