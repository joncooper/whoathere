const USERNAME = "whoathere";
const FALLBACK_PASSWORD = "licketysplit";
const REALM = "WhoaThere Codex Thread";

function unauthorized() {
  return new Response("Authentication required", {
    status: 401,
    headers: {
      "WWW-Authenticate": `Basic realm="${REALM}", charset="UTF-8"`,
      "Cache-Control": "no-store",
    },
  });
}

function timingSafeEqual(left, right) {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  const max = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;

  for (let i = 0; i < max; i += 1) {
    diff |= (a[i] || 0) ^ (b[i] || 0);
  }

  return diff === 0;
}

function credentials(request) {
  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Basic ")) {
    return null;
  }

  try {
    const decoded = atob(header.slice("Basic ".length));
    const split = decoded.indexOf(":");
    if (split < 0) {
      return null;
    }
    return {
      username: decoded.slice(0, split),
      password: decoded.slice(split + 1),
    };
  } catch {
    return null;
  }
}

export default {
  async fetch(request, env) {
    const supplied = credentials(request);
    const password = env.BASIC_AUTH_PASSWORD || FALLBACK_PASSWORD;
    const allowed =
      supplied &&
      timingSafeEqual(supplied.username, USERNAME) &&
      timingSafeEqual(supplied.password, password);

    if (!allowed) {
      return unauthorized();
    }

    const response = await env.ASSETS.fetch(request);
    const headers = new Headers(response.headers);
    headers.set("X-Robots-Tag", "noindex, nofollow");

    if (response.headers.get("content-type")?.includes("text/html")) {
      headers.set("Cache-Control", "private, no-store");
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  },
};
