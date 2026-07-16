import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const allowedOrigins = new Set([
  "https://cantinhodalu.site",
  "https://www.cantinhodalu.site",
  "http://127.0.0.1:5500",
  "http://localhost:5500",
]);

const allowedEvents = new Set([
  "page_view",
  "wheel_open",
  "spin_started",
  "prize_won",
  "whatsapp_click",
  "ifood_click",
  "prize_whatsapp_click",
]);

function buildCorsHeaders(origin: string | null) {
  const allowedOrigin =
    origin && allowedOrigins.has(origin)
      ? origin
      : "https://cantinhodalu.site";

  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Headers":
      "authorization, x-client-info, apikey, content-type",
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

  const encoded = new TextEncoder().encode(`${visitorId}:${secret}`);
  const digest = await crypto.subtle.digest("SHA-256", encoded);

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function sanitizeMetadata(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return {};
  }

  const entries = Object.entries(input as Record<string, unknown>);
  const metadata: Record<string, string | number | boolean | null> = {};

  for (const [key, value] of entries) {
    if (typeof key !== "string") {
      continue;
    }

    if (typeof value === "string") {
      metadata[key] = value.slice(0, 300);
      continue;
    }

    if (typeof value === "number" && Number.isFinite(value)) {
      metadata[key] = value;
      continue;
    }

    if (typeof value === "boolean" || value === null) {
      metadata[key] = value;
    }
  }

  const keys = Object.keys(metadata);
  if (keys.length > 20) {
    const limited: Record<string, string | number | boolean | null> = {};
    for (const key of keys.slice(0, 20)) {
      limited[key] = metadata[key];
    }
    return limited;
  }

  return metadata;
}

Deno.serve(async (request) => {
  const origin = request.headers.get("origin");
  const headers = buildCorsHeaders(origin);

  if (request.method === "OPTIONS") {
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
    const rawBody = await request.text();

    if (rawBody.length > 65536) {
      return jsonResponse(
        {
          ok: false,
          reason: "INVALID_REQUEST",
          message: "Payload muito grande.",
        },
        400,
        headers,
      );
    }

    let payload: Record<string, unknown> = {};

    if (rawBody) {
      try {
        payload = JSON.parse(rawBody) as Record<string, unknown>;
      } catch {
        payload = {};
      }
    }

    const eventName =
      typeof payload.eventName === "string"
        ? payload.eventName.trim()
        : "";

    if (!allowedEvents.has(eventName)) {
      return jsonResponse(
        {
          ok: false,
          reason: "INVALID_EVENT",
          message: "Evento inválido.",
        },
        400,
        headers,
      );
    }

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

    const campaignSlug =
      typeof payload.campaignSlug === "string"
        ? payload.campaignSlug.trim()
        : "";

    if (campaignSlug.length > 100) {
      return jsonResponse(
        {
          ok: false,
          reason: "INVALID_CAMPAIGN",
          message: "Campanha inválida.",
        },
        400,
        headers,
      );
    }

    let prizeCode: string | null = null;
    if (payload.prizeCode !== undefined && payload.prizeCode !== null) {
      if (typeof payload.prizeCode !== "string") {
        return jsonResponse(
          {
            ok: false,
            reason: "INVALID_PRIZE_CODE",
            message: "Código do prêmio inválido.",
          },
          400,
          headers,
        );
      }

      prizeCode = payload.prizeCode.trim();
      if (prizeCode.length > 100) {
        return jsonResponse(
          {
            ok: false,
            reason: "INVALID_PRIZE_CODE",
            message: "Código do prêmio inválido.",
          },
          400,
          headers,
        );
      }
    }

    const metadataInput = payload.metadata;
    if (
      metadataInput !== undefined &&
      metadataInput !== null &&
      (typeof metadataInput !== "object" || Array.isArray(metadataInput))
    ) {
      return jsonResponse(
        {
          ok: false,
          reason: "INVALID_METADATA",
          message: "Metadata inválida.",
        },
        400,
        headers,
      );
    }

    const metadata = sanitizeMetadata(metadataInput);

    const userAgent = request.headers.get("user-agent") ?? "";
    const referrer =
      typeof metadataInput === "object" && metadataInput !== null && !Array.isArray(metadataInput)
        ? (metadataInput as Record<string, unknown>).referrer
        : undefined;
    const pagePath =
      typeof metadataInput === "object" && metadataInput !== null && !Array.isArray(metadataInput)
        ? (metadataInput as Record<string, unknown>).page_path
        : undefined;

    const enrichedMetadata = {
      ...metadata,
      origin: origin ?? "",
      user_agent: userAgent.slice(0, 300),
      page_path:
        typeof pagePath === "string"
          ? pagePath.slice(0, 300)
          : "",
      referrer:
        typeof referrer === "string"
          ? referrer.slice(0, 300)
          : "",
      utm_source:
        typeof metadata.utm_source === "string"
          ? metadata.utm_source.slice(0, 300)
          : "",
      utm_medium:
        typeof metadata.utm_medium === "string"
          ? metadata.utm_medium.slice(0, 300)
          : "",
      utm_campaign:
        typeof metadata.utm_campaign === "string"
          ? metadata.utm_campaign.slice(0, 300)
          : "",
      utm_content:
        typeof metadata.utm_content === "string"
          ? metadata.utm_content.slice(0, 300)
          : "",
      utm_term:
        typeof metadata.utm_term === "string"
          ? metadata.utm_term.slice(0, 300)
          : "",
    };

    const visitorHash = await createVisitorHash(visitorId);

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!supabaseUrl || !serviceRoleKey) {
      throw new Error("Supabase server variables unavailable.");
    }

    const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });

    let campaignId: number | null = null;
    if (campaignSlug) {
      const { data: campaignData, error: campaignError } = await supabaseAdmin
        .schema("promo")
        .from("campaigns")
        .select("id")
        .eq("slug", campaignSlug)
        .maybeSingle();

      if (!campaignError) {
        campaignId = campaignData?.id ?? null;
      }
    }

    let prizeId: number | null = null;
    if (prizeCode) {
      const { data: prizeData, error: prizeError } = await supabaseAdmin
        .schema("promo")
        .from("prizes")
        .select("id")
        .eq("code", prizeCode)
        .maybeSingle();

      if (!prizeError) {
        prizeId = prizeData?.id ?? null;
      }
    }

    const { error: insertError } = await supabaseAdmin
      .schema("promo")
      .from("analytics_events")
      .insert({
        event_name: eventName,
        visitor_hash: visitorHash,
        campaign_id: campaignId,
        prize_id: prizeId,
        metadata: enrichedMetadata,
      });

    if (insertError) {
      console.error("analytics insert error:", insertError);
      return jsonResponse(
        {
          ok: false,
          reason: "INTERNAL_ERROR",
          message: "Não foi possível registrar o evento.",
        },
        500,
        headers,
      );
    }

    return jsonResponse({ ok: true }, 201, headers);
  } catch (error) {
    console.error("track-event error:", error);

    return jsonResponse(
      {
        ok: false,
        reason: "INTERNAL_ERROR",
        message: "Não foi possível registrar o evento.",
      },
      500,
      headers,
    );
  }
});
