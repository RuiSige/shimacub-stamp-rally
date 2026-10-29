
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      const result = await env.DB.prepare(
        "SELECT 1 AS ok"
      ).first();

      return Response.json({
        status: "ok",
        database: result?.ok === 1
      });
    }

    return env.ASSETS.fetch(request);
  }
};
