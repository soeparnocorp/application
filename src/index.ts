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
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    // ============================================================
    // 1. ROUTING SYSTEM (internal OpenAuth)
    // ============================================================
    const url = new URL(request.url);
    
    // Root → redirect ke authorize
    if (url.pathname === "/") {
      url.searchParams.set("redirect_uri", "https://app-readtalk.pages.dev/callback");
      url.searchParams.set("client_id", "readtalk");
      url.searchParams.set("response_type", "code");
      url.pathname = "/authorize";
      return Response.redirect(url.toString());
    }
    
    // Callback → tukar code dengan token
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");
      // logic tukar code dengan token
      return Response.json({ token });
    }

    // ============================================================
    // 2. LOADER LOGIC (ambil data user dari database)
    // ============================================================
    async function getUser(email: string) {
      const result = await env.AUTH_DB.prepare(
        "SELECT id FROM users WHERE email = ?"
      ).bind(email).first();
      return result;
    }

    async function createUser(email: string) {
      const id = crypto.randomUUID();
      await env.AUTH_DB.prepare(
        "INSERT INTO users (id, email) VALUES (?, ?)"
      ).bind(id, email).run();
      return { id };
    }

    // ============================================================
    // 3. FORM HANDLING (via PasswordProvider)
    // 4. ERROR HANDLING (otomatis dari library)
    // 5. LOADING STATE (otomatis dari library)
    // ============================================================
    return issuer({
      storage: CloudflareStorage({ namespace: env.AUTH_STORAGE }),
      subjects,
      providers: {
        password: PasswordProvider(
          PasswordUI({
            sendCode: async (email, code) => {
              console.log(`[OpenAuth] Sending code ${code} to ${email}`);
              // Nanti bisa diganti dengan email service
            },
            copy: {
              input_code: "Code (check Worker logs)",
            },
          }),
        ),
      },
      
      // ============================================================
      // 6. SESSION MANAGEMENT (token creation)
      // ============================================================
      success: async (ctx, value) => {
        // Dapatkan atau buat user
        const user = await getUser(value.email) || await createUser(value.email);
        
        // Buat subject (token) untuk user
        return ctx.subject("user", {
          id: user.id,
        });
      },
      
      theme: {
        title: "READTalk - OpenAuth",
        primary: "#0284c7",
        favicon: "https://raw.githubusercontent.com/soeparnocorp/openauth/main/public/favicon.ico",
        logo: {
          dark: "https://raw.githubusercontent.com/soeparnocorp/openauth/main/src/logo-dark.png",
          light: "https://raw.githubusercontent.com/soeparnocorp/openauth/main/src/logo-light.png",
        },
      },
    }).fetch(request, env, ctx);
  },
};
