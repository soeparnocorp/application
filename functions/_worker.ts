import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

const subjects = createSubjects({
  user: object({ id: string() }),
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);
    
    if (url.pathname === "/") {
      url.pathname = "/authorize";
      url.searchParams.set("client_id", "readtalk");
      url.searchParams.set("redirect_uri", "https://app-readtalk.pages.dev/callback");
      return Response.redirect(url.toString(), 302);
    }

    return issuer({
      storage: CloudflareStorage({ namespace: env.AUTH_STORAGE }),
      subjects,
      providers: {
        password: PasswordProvider(
          PasswordUI({
            sendCode: async (email, code) => {
              console.log(`[OpenAuth] Code ${code} → ${email}`);
            }
          })
        ),
      },
      success: async (ctx, value) => {
        const userId = await getOrCreateUser(env, value.email);
        return ctx.subject("user", { id: userId });
      },
    }).fetch(request, env, ctx);
  },
};

async function getOrCreateUser(env: Env, email: string): Promise<string> {
  const result = await env.AUTH_DB.prepare(`
    INSERT INTO user (email) VALUES (?)
    ON CONFLICT (email) DO UPDATE SET email = email
    RETURNING id;
  `).bind(email).first<{ id: string }>();
  
  return result!.id;
}

interface Env {
  AUTH_STORAGE: KVNamespace;
  AUTH_DB: D1Database;
}
