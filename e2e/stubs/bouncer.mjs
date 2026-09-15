// A stand-in for Bouncer's access endpoint, so the end-to-end stack signs
// administrators in through the real OAuth + role-check path without a real
// Bouncer deployment.
//
// It grants the admin role to one subject, and only when Clerk presents the
// expected API key. Everything else is refused the way Bouncer refuses it.
import { createServer } from "node:http";

const port = Number(process.env.PORT ?? 8082);
const apiKey = process.env.BOUNCER_API_KEY;
const adminSub = process.env.BOUNCER_ADMIN_SUB;
const adminProvider = process.env.BOUNCER_ADMIN_PROVIDER ?? "google";

if (!apiKey || !adminSub) {
  console.error("BOUNCER_API_KEY and BOUNCER_ADMIN_SUB are required");
  process.exit(1);
}

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");

  if (req.method === "GET" && url.pathname === "/health") {
    return send(res, 200, { status: "ok" });
  }
  if (req.method !== "GET" || url.pathname !== "/api/v1/access") {
    return send(res, 404, { error: "not_found" });
  }
  if (req.headers.authorization !== `Bearer ${apiKey}`) {
    return send(res, 401, { error: "invalid_api_key" });
  }

  const sub = url.searchParams.get("sub");
  const provider = url.searchParams.get("provider");
  if (sub !== adminSub || provider !== adminProvider) {
    return send(res, 404, { error: "user_not_found" });
  }
  send(res, 200, { sub, role: { customId: "admin", name: "Administrator" } });
}).listen(port, () => console.log(`bouncer stub listening on :${port}`));
