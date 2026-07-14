import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const allowedOrigins = new Set([
  "https://cantinhodalu.site",
  "https://www.cantinhodalu.site",
  "http://127.0.0.1:5500",
  "http://localhost:5500",
]);

function buildCorsHeaders(origin: string | null) {
  const allowedOrigin =
    origin && allowedOrigins.has(origin)
      ? origin
      : "https://cantinhodalu.site";

  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Headers":
      "authorization, x-client-info, apikey, content-type, x-visitor-id",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Content-Type": "application/json; charset=utf-8",
    Vary: "Origin",
  };
}

function jsonResponse(
  body: unknown,
  status: number,
  headers: Record<string, string>,
) {
  return new Response(JSON.stringify(body), {
    status,
    headers,
  });
}

async function createVisitorHash(visitorId: string) {
  const secret =
    Deno.env.get("VISITOR_HASH_SECRET") ??
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

  if (!secret) {
    throw new Error("Visitor secret unavailable.");
  }

  const encoded = new TextEncoder().encode(
    `${visitorId}:${secret}`,
  );

  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoded,
  );

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

Deno.serve(async (request) => {
  const origin = request.headers.get("origin");
  const headers = buildCorsHeaders(origin);

  if (request.method === "OPTIONS") {
    return new Response("ok", {
      status: 200,
      headers,
    });
  }

  if (request.method !== "POST") {
    return jsonResponse(
      {
        ok: false,
        reason: "METHOD_NOT_ALLOWED",
        message: "Método não permitido.",
      },
      405,
      headers,
    );
  }

  if (origin && !allowedOrigins.has(origin)) {
    return jsonResponse(
      {
        ok: false,
        reason: "ORIGIN_NOT_ALLOWED",
        message: "Origem não autorizada.",
      },
      403,
      headers,
    );
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get(
      "SUPABASE_SERVICE_ROLE_KEY",
    );

    if (!supabaseUrl || !serviceRoleKey) {
      throw new Error("Supabase server variables unavailable.");
    }

    const payload = await request.json().catch(() => ({}));

    const visitorId =
      typeof payload.visitorId === "string"
        ? payload.visitorId.trim()
        : "";

    if (visitorId.length < 20 || visitorId.length > 200) {
      return jsonResponse(
        {
          ok: false,
          reason: "INVALID_VISITOR_ID",
          message: "Identificador do visitante inválido.",
        },
        400,
        headers,
      );
    }

    const visitorHash = await createVisitorHash(visitorId);

    const supabaseAdmin = createClient(
      supabaseUrl,
      serviceRoleKey,
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
        },
      },
    );

    const userAgent =
      request.headers.get("user-agent") ?? "";

    const forwardedFor =
      request.headers.get("x-forwarded-for") ?? "";

    const requestMetadata = {
      user_agent: userAgent.slice(0, 500),
      ip_hint: forwardedFor.split(",")[0]?.trim() ?? "",
      origin: origin ?? "",
    };

    const { data, error } = await supabaseAdmin
      .schema("promo")
      .rpc("claim_welcome_spin", {
        p_campaign_slug: "welcome-wheel",
        p_visitor_hash: visitorHash,
        p_request_metadata: requestMetadata,
      });

    if (error) {
      console.error("RPC error:", error);

      return jsonResponse(
        {
          ok: false,
          reason: "DATABASE_ERROR",
          message: "Não foi possível realizar o sorteio.",
        },
        500,
        headers,
      );
    }

    return jsonResponse(data, 200, headers);
  } catch (error) {
    console.error("spin-wheel error:", error);

    return jsonResponse(
      {
        ok: false,
        reason: "INTERNAL_ERROR",
        message: "Não foi possível processar sua tentativa.",
      },
      500,
      headers,
    );
  }
});