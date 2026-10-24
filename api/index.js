const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');

let _db;
const db = () => (_db = _db || neon(process.env.DATABASE_URL)); // se crea al usarse, para que un error salga como mensaje y no tumbe la función
const sql = (...a) => db()(...a);
const SEC = process.env.SESSION_SECRET || '';
const dig = s => crypto.createHash('sha256').update(String(s)).digest();
const sign = t => crypto.createHmac('sha256', SEC).update(t).digest('hex');
const uid = () => crypto.randomBytes(6).toString('hex');
const wait = ms => new Promise(r => setTimeout(r, ms));
const scrypt = (p, salt) => new Promise((ok, no) => crypto.scrypt(String(p), salt, 32, (e, k) => (e ? no(e) : ok(k))));
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);

// campos que se pueden modificar después de creado un registro
const ALLOW = { ventas: ['cob', 'est'], alq: ['cob', 'est'], asis: ['e', 's', 'h', 'pag', 'd', 'a'], gas: [], mant: [], pagos: [], poli: [], com: [], abo: [], fac: [], caja: [] };

function autenticado(req) {
  const m = (req.headers.cookie || '').match(/fc=([^;]+)/);
  if (!m || !SEC) return false;
  const [e, g] = m[1].split('.');
  if (!e || !g || Date.now() > +e) return false;
  return eq(Buffer.from(sign(e)), Buffer.from(g));
}
const aud = accion => sql`insert into auditoria(accion) values(${accion})`;
const bad = (res, e, c = 400) => res.status(c).json({ e });

// ---- credenciales: si existen en la base (config 'auth') mandan; si no, se usan ADMIN_USER / ADMIN_PASS de Vercel
const envU = () => (process.env.ADMIN_USER || '').trim();
const envP = () => (process.env.ADMIN_PASS || '').trim();
async function getAuth() {
  const r = await sql`select v from config where k='auth'`;
  return r.length ? r[0].v : null;
}
async function passOk(p, a) {
  p = String(p || '');
  if (a) return eq(await scrypt(p, Buffer.from(a.s, 'hex')), Buffer.from(a.h, 'hex'));
  return !!envP() && eq(dig(p), dig(envP()));
}

module.exports = async (req, res) => {
  try {
    // Ver foto de un recibo
    if (req.method === 'GET') {
      if (!autenticado(req)) return res.status(401).end();
      const r = await sql`select img from fotos where id=${String(req.query.id || '')}`;
      if (!r.length) return res.status(404).end();
      const m = r[0].img.match(/^data:(.+?);base64,(.+)$/);
      res.setHeader('Content-Type', m[1]);
      res.setHeader('Cache-Control', 'private, max-age=86400');
      return res.send(Buffer.from(m[2], 'base64'));
    }
    const b = req.body || {};

    if (b.a === 'login') {
      const a = await getAuth();
      if (!SEC || (!a && (!envU() || !envP()))) return bad(res, 'Faltan variables en Vercel: ' + [!SEC && 'SESSION_SECRET', !a && !envU() && 'ADMIN_USER', !a && !envP() && 'ADMIN_PASS'].filter(Boolean).join(', ') + '. Agrégalas y haz Redeploy.', 500);
      const u = String(b.u || '').trim().toLowerCase();
      const okU = eq(dig(u), dig(String(a ? a.u : envU()).toLowerCase()));
      const okP = await passOk(b.p, a);
      if (!(okU && okP)) {
        await wait(900);
        return bad(res, 'Usuario o contraseña incorrectos', 401);
      }
      const e = String(Date.now() + 12 * 3600e3);
      res.setHeader('Set-Cookie', `fc=${e}.${sign(e)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`);
      await aud('Ingreso al sistema');
      return res.json({ ok: 1 });
    }
    if (b.a === 'logout') {
      res.setHeader('Set-Cookie', 'fc=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
      return res.json({ ok: 1 });
    }
    if (!autenticado(req)) return bad(res, 'auth', 401);

    if (b.a === 'all') {
      const [c, r, l, t, a] = await Promise.all([
        sql`select k, v from config where k <> 'auth'`, // la clave/usuario nunca viajan al navegador
        sql`select id, tipo, f::text as f, data, anu from registros order by creado`,
        sql`select to_char(t at time zone 'America/Lima','YYYY-MM-DD HH24:MI') as t, accion from auditoria order by id desc limit 40`,
        sql`select to_char(now() at time zone 'America/Lima','YYYY-MM-DD') as f`,
        getAuth()
      ]);
      return res.json({ cfg: Object.fromEntries(c.map(x => [x.k, x.v])), regs: r, log: l, hoy: t[0].f, usr: a ? a.u : envU() });
    }

    // Cambiar usuario y/o contraseña desde dentro del sistema
    if (b.a === 'cred') {
      const nu = String(b.nu || '').trim(), np = String(b.np || '');
      if (!nu && !np) return bad(res, 'No hay nada que cambiar');
      if (nu && nu.length < 3) return bad(res, 'El usuario debe tener al menos 3 caracteres');
      if (np && np.length < 6) return bad(res, 'La contraseña debe tener al menos 6 caracteres');
      const a = await getAuth();
      if (!(await passOk(b.p, a))) {
        await wait(900);
        return bad(res, 'La contraseña actual no es correcta', 403);
      }
      const salt = (!np && a) ? Buffer.from(a.s, 'hex') : crypto.randomBytes(16);
      const hash = (!np && a) ? Buffer.from(a.h, 'hex') : await scrypt(np || b.p, salt);
      const nuevo = { u: nu || (a ? a.u : envU()), s: salt.toString('hex'), h: hash.toString('hex') };
      await sql`insert into config(k,v) values('auth', ${JSON.stringify(nuevo)}::jsonb)
                on conflict (k) do update set v = excluded.v`;
      await aud('Cambio de ' + [nu && 'usuario', np && 'contraseña'].filter(Boolean).join(' y '));
      return res.json({ ok: 1 });
    }

    if (b.a === 'cfg') {
      await sql`insert into config(k,v) values('cfg', ${JSON.stringify(b.cfg || {})}::jsonb)
                on conflict (k) do update set v = excluded.v`;
      let acc = 'Configuración actualizada';
      if (Array.isArray(b.ren) && b.ren.length === 2) {
        await sql`update registros set data = jsonb_set(data,'{c}', to_jsonb(${String(b.ren[1])}::text)) where data->>'c' = ${String(b.ren[0])}`;
        acc += ` · ${b.ren[0]} → ${b.ren[1]}`;
      }
      await aud(acc);
      return res.json({ ok: 1 });
    }

    // Petróleo para varios vehículos a la vez: una sola foto, todo o nada (transacción)
    if (b.a === 'gasmulti') {
      const L = Array.isArray(b.recs) ? b.recs : [], img = b.img;
      if (!L.length || L.length > 30) return bad(res, 'Elige al menos un vehículo');
      if (!img || img.length > 900000) return bad(res, 'La foto del recibo es obligatoria');
      const [{ f: hoy }] = await sql`select to_char(now() at time zone 'America/Lima','YYYY-MM-DD') as f`;
      const fecha = /^\d{4}-\d\d-\d\d$/.test(b.f || '') ? b.f : hoy;
      const q = db(), ids = [], items = [];
      for (const r of L) {
        const d = { c: String(r.c || ''), m: String(r.m || ''), mon: +r.mon, gal: +r.gal || 0, n: String(r.n || ''), foto: 1 };
        if (!d.m) return bad(res, 'Falta el vehículo');
        if (!(d.mon > 0)) return bad(res, 'Monto inválido');
        const id = uid(); ids.push(id);
        items.push(q`insert into registros(id,tipo,f,data) values(${id}, 'gas', ${fecha}, ${JSON.stringify(d)}::jsonb)`);
        items.push(q`insert into fotos(id,img) values(${id}, ${img})`);
      }
      items.push(q`insert into auditoria(accion) values(${'Alta gas (' + ids.length + ' vehículos) ' + ids.join(',')})`);
      await q.transaction(items);
      return res.json({ ids });
    }

    // Pasar dinero de una cuenta a otra (salida + entrada, todo o nada)
    if (b.a === 'cajatr') {
      const m = +b.mon, from = String(b.from || '').trim(), to = String(b.to || '').trim(), mot = String(b.mot || '').trim(), resp = String(b.resp || '').trim();
      if (!from || !to || from === to) return bad(res, 'Elige dos cuentas distintas');
      if (!(m > 0)) return bad(res, 'Monto inválido');
      if (mot.length < 3 || !resp) return bad(res, 'Falta el motivo o quién lo hizo');
      const [{ f: hoy }] = await sql`select to_char(now() at time zone 'America/Lima','YYYY-MM-DD') as f`;
      const q = db(), a = uid(), c = uid();
      await q.transaction([
        q`insert into registros(id,tipo,f,data) values(${a}, 'caja', ${hoy}, ${JSON.stringify({ cta: from, mon: m, sg: -1, k: 'transf', mot: 'Pasó a ' + to + ': ' + mot, resp })}::jsonb)`,
        q`insert into registros(id,tipo,f,data) values(${c}, 'caja', ${hoy}, ${JSON.stringify({ cta: to, mon: m, sg: 1, k: 'transf', mot: 'Vino de ' + from + ': ' + mot, resp })}::jsonb)`,
        q`insert into auditoria(accion) values(${'Transferencia entre cuentas ' + a + ',' + c})`
      ]);
      return res.json({ ids: [a, c] });
    }

    // Factura: el servidor asigna el correlativo (sin saltos) y calcula IGV
    if (b.a === 'facnew') {
      const r = b.rec || {}, ruc = String(r.ruc || '').replace(/\D/g, ''), rs = String(r.rs || '').trim().slice(0, 200), dir = String(r.dir || '').trim().slice(0, 250);
      const ser = /^F[A-Z0-9]{3}$/.test(String(r.ser || '')) ? r.ser : 'F001', cond = r.cond === 'Crédito' ? 'Crédito' : 'Contado', inc = r.inc !== false;
      if (!/^(10|15|16|17|20)\d{9}$/.test(ruc)) return bad(res, 'RUC del cliente inválido');
      if (rs.length < 3) return bad(res, 'Falta la razón social del cliente');
      const its = Array.isArray(r.items) ? r.items.slice(0, 50) : [];
      if (!its.length) return bad(res, 'La factura no tiene detalle');
      const r2 = n => Math.round(n * 100) / 100, items = []; let sp = 0;
      for (const i of its) {
        const q = +i.q, p = +i.p;
        if (!(q > 0 && p > 0)) return bad(res, 'Revisa cantidades y precios');
        const vu = inc ? Math.round(p / 1.18 * 1e4) / 1e4 : p;
        items.push({ d: String(i.d || '').slice(0, 200), u: String(i.u || 'UNIDAD').slice(0, 20), q, p, vu, vv: r2(q * vu) });
        sp += q * p;
      }
      let base, igv, tot;
      if (inc) { tot = r2(sp); base = r2(tot / 1.18); igv = r2(tot - base); }
      else { base = r2(items.reduce((a, i) => a + i.vv, 0)); igv = r2(base * 0.18); tot = r2(base + igv); }
      const refs = Array.isArray(r.refs) ? r.refs.map(String).slice(0, 50) : [];
      for (const id of refs) {
        const ok = await sql`select 1 from registros where id=${id} and tipo in ('ventas','alq') and anu is null`;
        if (!ok.length) return bad(res, 'Una de las ventas ya no es válida');
        const ya = await sql`select 1 from registros where tipo='fac' and anu is null and data->'refs' @> ${JSON.stringify([id])}::jsonb`;
        if (ya.length) return bad(res, 'Una de las ventas ya fue facturada');
      }
      const [{ f: hoy, h }] = await sql`select to_char(now() at time zone 'America/Lima','YYYY-MM-DD') as f, to_char(now() at time zone 'America/Lima','HH24:MI:SS') as h`;
      const d = { ser, ruc, rs, dir, cond, inc, items, base, igv, tot, refs, h };
      for (let k = 0; k < 3; k++) {
        const id = uid();
        try {
          const ins = await sql`insert into registros(id,tipo,f,data)
            select ${id}, 'fac', ${hoy}::date, ${JSON.stringify(d)}::jsonb || jsonb_build_object('num', q.n)
            from (select coalesce(max((data->>'num')::int),0)+1 as n from registros where tipo='fac' and data->>'ser'=${ser}) q
            returning (data->>'num')::int as num`;
          await aud(`Alta factura ${ser}-${String(ins[0].num).padStart(8, '0')} ${id}`);
          return res.json({ id, ser, num: ins[0].num });
        } catch (e) { if (!/duplicate|unique/i.test(e.message) || k === 2) throw e; }
      }
    }

    if (b.a === 'add') {
      const t = b.tipo;
      if (!Object.prototype.hasOwnProperty.call(ALLOW, t)) return bad(res, 'Tipo inválido');
      const d = { ...(b.rec || {}) };
      const img = d.img; delete d.img; delete d.id; delete d.anu;
      const [{ f: hoy, h }] = await sql`select to_char(now() at time zone 'America/Lima','YYYY-MM-DD') as f, to_char(now() at time zone 'America/Lima','HH24:MI:SS') as h`;
      let fecha = hoy;
      if (['gas', 'mant', 'poli', 'com'].includes(t) && /^\d{4}-\d\d-\d\d$/.test(d.f || '')) fecha = d.f;
      if (t === 'gas' || t === 'mant') {
        if (!img || img.length > 900000) return bad(res, 'La foto del recibo es obligatoria');
        d.foto = 1;
      }
      delete d.f;
      if (t === 'ventas') {
        d.h = h; d.q = +d.q; d.p = +d.p; d.tot = d.q * d.p;
        if (!(d.tot > 0)) return bad(res, 'Revisa cantidad y precio');
      }
      if (t === 'alq') {
        d.hr = +d.hr; d.p = +d.p; d.tot = d.hr * d.p;
        if (!(d.tot > 0)) return bad(res, 'Revisa horas y precio');
      }
      if (t === 'fac') return bad(res, 'Usa la acción de facturas');
      if (t === 'caja') {
        const sg = +d.sg === 1 ? 1 : -1, mot = String(d.mot || '').trim(), resp = String(d.resp || '').trim(), cta = String(d.cta || '').trim(), k = String(d.k || 'ajuste').slice(0, 20);
        const ant = d.ant, nuevo = d.nuevo;
        if (mot.length < 3 || !resp || !cta) return bad(res, 'Falta el motivo, la cuenta o quién lo hizo');
        for (const key of Object.keys(d)) delete d[key];
        Object.assign(d, { cta, mon: +b.rec.mon, sg, k, mot, resp });
        if (isFinite(+ant) && ant !== null && ant !== '') d.ant = +ant;
        if (isFinite(+nuevo) && nuevo !== null && nuevo !== '') d.nuevo = +nuevo;
      }
      if (['gas', 'mant', 'pagos', 'poli', 'com', 'abo', 'caja'].includes(t)) { d.mon = +d.mon; if (!(d.mon > 0)) return bad(res, 'Monto inválido'); }
      if (t === 'abo') {
        const rf = await sql`select 1 from registros where id=${String(d.ref)} and tipo in ('ventas','alq') and anu is null`;
        if (!rf.length) return bad(res, 'No existe la deuda a la que se quiere abonar');
      }
      if (t === 'asis') {
        const dup = await sql`select 1 from registros where tipo='asis' and f=${fecha} and data->>'c'=${String(d.c)}`;
        if (dup.length) return bad(res, 'Ya hay asistencia de hoy para este trabajador');
      }
      const id = uid();
      await sql`insert into registros(id,tipo,f,data) values(${id}, ${t}, ${fecha}, ${JSON.stringify(d)}::jsonb)`;
      if (img) await sql`insert into fotos(id,img) values(${id}, ${img})`;
      await aud(`Alta ${t} ${id}`);
      return res.json({ id });
    }

    if (b.a === 'upd') {
      const r = (await sql`select tipo, data, anu from registros where id=${String(b.id)}`)[0];
      if (!r) return bad(res, 'No existe', 404);
      if (r.anu) return bad(res, 'Registro anulado');
      const p = {};
      for (const k of ALLOW[r.tipo]) if (b.patch && k in b.patch) p[k] = b.patch[k];
      if (r.tipo === 'asis' && r.data.pag && 'h' in p && +p.h !== +r.data.h) return bad(res, 'Horas extra ya pagadas');
      await sql`update registros set data=${JSON.stringify({ ...r.data, ...p })}::jsonb where id=${String(b.id)}`;
      await aud(`Modificación ${r.tipo} ${b.id}: ${Object.keys(p).join(',')}`);
      return res.json({ ok: 1 });
    }

    if (b.a === 'anu') {
      if (!b.m || String(b.m).trim().length < 3) return bad(res, 'Motivo obligatorio');
      const r = await sql`update registros set anu=${JSON.stringify({ m: String(b.m), t: new Date().toISOString() })}::jsonb
                          where id=${String(b.id)} and anu is null and tipo<>'asis' returning id`;
      if (!r.length) return bad(res, 'No se puede anular');
      await aud(`Anulado ${b.id}: ${b.m}`);
      return res.json({ ok: 1 });
    }
    return bad(res, 'Acción desconocida');
  } catch (e) {
    return res.status(500).json({ e: 'Error del servidor: ' + e.message });
  }
};
