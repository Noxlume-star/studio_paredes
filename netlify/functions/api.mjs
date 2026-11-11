
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const J = (o, s = 200) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store"
    }
  });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const sig = (e) =>
  crypto.createHmac("sha256", process.env.ADMIN_PASSWORD || "")
    .update(String(e))
    .digest("hex");

const token = () => {
  const e = Date.now() + 12 * 3600e3;
  return e + "." + sig(e);
};

const valid = (t) => {
  if (!process.env.ADMIN_PASSWORD || !t) return false;

  const [e, s] = t.split(".");
  if (!e || !s || +e < Date.now()) return false;

  const a = Buffer.from(s);
  const b = Buffer.from(sig(e));

  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const hashPw = (pw) => {
  const salt = crypto.randomBytes(16).toString("hex");

  return {
    salt,
    hash: crypto.scryptSync(String(pw), salt, 32).toString("hex")
  };
};

const same = (pw, rec) => {
  if (!rec || !rec.salt) return false;

  const a = Buffer.from(
    crypto.scryptSync(String(pw), rec.salt, 32).toString("hex")
  );

  const b = Buffer.from(rec.hash);

  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const sha = (x) =>
  crypto.createHash("sha256").update(String(x)).digest();

const mkCode = () => {
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const b = crypto.randomBytes(16);

  let s = "";

  for (let i = 0; i < 16; i++) {
    s += A[b[i] % A.length];

    if (i % 4 === 3 && i < 15) s += "-";
  }

  return s;
};

const clean = (c) =>
  String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");

// ===== SUPABASE STORAGE =====

const BUCKET = "STUDIO-PHOTOS";

const getSupabaseConfig = () => {
  const url = process.env.SUPABASE_URL?.replace(/\/+$/, "");
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    throw new Error("Falta configurar Supabase en Netlify");
  }

  return { url, key };
};

const storageHeaders = (key) => ({
  apikey: key,
  Authorization: `Bearer ${key}`
});

const storageObjectUrl = (url, id) =>
  `${url}/storage/v1/object/${encodeURIComponent(BUCKET)}/${encodeURIComponent(id)}`;

// ===== API =====

export default async (req) => {
  const url = new URL(req.url);
  const p = url.pathname.replace(/^\/api\//, "").split("/");
  const m = req.method;

  const db = getStore("studio");
  const rv = getStore("reviews");
  const au = getStore("auth");

  const rl = async () =>
    (await rv.get("all", { type: "json" })) || [];

  // ===== CONTENIDO PÚBLICO =====

  if (p[0] === "content" && m === "GET") {
    return J(await db.get("content", { type: "json" }));
  }

  // ===== OBTENER FOTOGRAFÍA DESDE SUPABASE =====

  if (p[0] === "photo" && m === "GET") {
    const id = p[1];

    if (!id || !/^[a-f0-9-]{36}$/i.test(id)) {
      return new Response("", { status: 404 });
    }

    try {
      const { url: supabaseUrl, key } = getSupabaseConfig();

      const response = await fetch(
        storageObjectUrl(supabaseUrl, id),
        {
          method: "GET",
          headers: storageHeaders(key)
        }
      );

      if (!response.ok) {
        return new Response("", {
          status: response.status === 404 ? 404 : 502
        });
      }

      return new Response(response.body, {
        status: 200,
        headers: {
          "content-type":
            response.headers.get("content-type") || "image/jpeg",
          "cache-control": "public, max-age=31536000, immutable"
        }
      });

    } catch (error) {
      console.error("Error cargando fotografía:", error);

      return J({ error: "No se pudo cargar la fotografía" }, 500);
    }
  }

  // ===== RESEÑAS PÚBLICAS =====

  if (p[0] === "reviews" && m === "GET") {
    const all = await rl();

    const adm =
      valid(req.headers.get("x-token")) &&
      url.searchParams.get("all");

    return J(
      adm
        ? all
        : all.filter((r) => r.show).map(({ n, t, r, ts }) => ({
            n,
            t,
            r,
            ts
          }))
    );
  }

  // ===== CREAR RESEÑA =====

  if (p[0] === "review" && m === "POST") {
    const b = await req.json().catch(() => ({}));

    if (b.hp) return J({ ok: 1 });

    const n = String(b.n || "").trim().slice(0, 60);
    const t = String(b.t || "").trim().slice(0, 600);
    const r = Math.round(+b.r);

    if (!n || t.length < 5 || !(r >= 1 && r <= 5)) {
      return J(
        { error: "Completa tu nombre, tu opinión y las estrellas" },
        400
      );
    }

    const all = await rl();

    if (all.length >= 300) {
      return J({ error: "Intenta más tarde" }, 429);
    }

    all.unshift({
      id: crypto.randomUUID(),
      n,
      t,
      r,
      ts: Date.now(),
      show: false
    });

    await rv.setJSON("all", all);

    return J({ ok: 1 });
  }

  // ===== INICIAR SESIÓN =====

  if (p[0] === "login" && m === "POST") {
    const { password } = await req.json().catch(() => ({}));

    const w = process.env.ADMIN_PASSWORD;
    const own = await au.get("pw", { type: "json" });

    const okMaster =
      w && crypto.timingSafeEqual(sha(password || ""), sha(w));

    if (!w || !(okMaster || same(password || "", own))) {
      await sleep(1200);
      return J({ error: "Contraseña incorrecta" }, 401);
    }

    return J({ token: token() });
  }

  // ===== RECUPERAR CONTRASEÑA =====

  if (p[0] === "recover" && m === "POST") {
    if (!process.env.ADMIN_PASSWORD) {
      return J({ error: "Falta configurar el sitio" }, 500);
    }

    const b = await req.json().catch(() => ({}));
    const st = await au.get("rc", { type: "json" });

    if (!st) {
      return J(
        { error: "Aún no hay un código de recuperación creado" },
        400
      );
    }

    if (st.lock && st.lock > Date.now()) {
      return J(
        { error: "Demasiados intentos. Intenta en 15 minutos" },
        429
      );
    }

    if (String(b.password || "").length < 8) {
      return J(
        { error: "La contraseña nueva debe tener 8 caracteres o más" },
        400
      );
    }

    if (!same(clean(b.code), st)) {
      st.tries = (st.tries || 0) + 1;

      if (st.tries >= 8) {
        st.lock = Date.now() + 15 * 60e3;
        st.tries = 0;
      }

      await au.setJSON("rc", st);
      await sleep(1200);

      return J({ error: "Código incorrecto" }, 401);
    }

    await au.setJSON("pw", hashPw(b.password));

    const nc = mkCode();

    await au.setJSON("rc", hashPw(clean(nc)));

    return J({ token: token(), code: nc });
  }

  // ===== PROTEGER RUTAS ADMINISTRATIVAS =====

  if (!valid(req.headers.get("x-token"))) {
    return J({ error: "Sesión vencida, entra de nuevo" }, 401);
  }

  // ===== INFORMACIÓN DE AUTENTICACIÓN =====

  if (p[0] === "auth-info" && m === "GET") {
    return J({
      hasOwn: !!(await au.get("pw", { type: "json" })),
      hasRecovery: !!(await au.get("rc", { type: "json" }))
    });
  }

  // ===== CAMBIAR CONTRASEÑA =====

  if (p[0] === "password" && m === "POST") {
    const b = await req.json().catch(() => ({}));

    if (String(b.password || "").length < 8) {
      return J({ error: "Mínimo 8 caracteres" }, 400);
    }

    await au.setJSON("pw", hashPw(b.password));

    return J({ ok: 1 });
  }

  // ===== GENERAR CÓDIGO DE RECUPERACIÓN =====

  if (p[0] === "recovery" && m === "POST") {
    const nc = mkCode();

    await au.setJSON("rc", hashPw(clean(nc)));

    return J({ code: nc });
  }

  // ===== GUARDAR CONTENIDO =====

  if (p[0] === "content" && m === "PUT") {
    const t = await req.text();

    if (t.length > 200000) {
      return J({ error: "Demasiado grande" }, 413);
    }

    let d;

    try {
      d = JSON.parse(t);
    } catch {
      return J({ error: "Datos inválidos" }, 400);
    }

    await db.setJSON("content", d);

    return J({ ok: 1 });
  }

  // ===== SUBIR FOTOGRAFÍA A SUPABASE =====

  if (p[0] === "upload" && m === "POST") {
    const type = req.headers.get("content-type") || "";

    if (!/^image\/(jpeg|png|webp)$/.test(type)) {
      return J({ error: "Solo imágenes" }, 415);
    }

    const buf = await req.arrayBuffer();

    if (buf.byteLength > 6e6) {
      return J({ error: "Foto muy pesada" }, 413);
    }

    try {
      const { url: supabaseUrl, key } = getSupabaseConfig();

      const id = crypto.randomUUID();

      const response = await fetch(
        storageObjectUrl(supabaseUrl, id),
        {
          method: "POST",
          headers: {
            ...storageHeaders(key),
            "content-type": type,
            "cache-control": "31536000",
            "x-upsert": "false"
          },
          body: buf
        }
      );

      if (!response.ok) {
        const details = await response.text();

        console.error("Error de Supabase Storage:", details);

        return J(
          { error: "No se pudo guardar la fotografía en Supabase" },
          502
        );
      }

      return J({ id });

    } catch (error) {
      console.error("Error subiendo fotografía:", error);

      return J(
        { error: "Error al conectar con Supabase" },
        500
      );
    }
  }

  // ===== ELIMINAR FOTOGRAFÍA DE SUPABASE =====

  if (p[0] === "photo" && m === "DELETE") {
    const id = p[1];

    if (!id || !/^[a-f0-9-]{36}$/i.test(id)) {
      return J({ error: "Fotografía inválida" }, 400);
    }

    try {
      const { url: supabaseUrl, key } = getSupabaseConfig();

      const response = await fetch(
        storageObjectUrl(supabaseUrl, id),
        {
          method: "DELETE",
          headers: storageHeaders(key)
        }
      );

      if (!response.ok && response.status !== 404) {
        const details = await response.text();

        console.error("Error eliminando fotografía:", details);

        return J(
          { error: "No se pudo eliminar la fotografía" },
          502
        );
      }

      return J({ ok: 1 });

    } catch (error) {
      console.error("Error eliminando fotografía:", error);

      return J(
        { error: "Error al conectar con Supabase" },
        500
      );
    }
  }

  // ===== ADMINISTRAR RESEÑAS =====

  if (p[0] === "review" && (m === "PATCH" || m === "DELETE")) {
    let all = await rl();

    if (m === "DELETE") {
      all = all.filter((x) => x.id !== p[1]);
    } else {
      const b = await req.json().catch(() => ({}));

      all = all.map((x) =>
        x.id === p[1] ? { ...x, show: !!b.show } : x
      );
    }

    await rv.setJSON("all", all);

    return J({ ok: 1 });
  }

  return J({ error: "No encontrado" }, 404);
};

export const config = { path: "/api/*" };
