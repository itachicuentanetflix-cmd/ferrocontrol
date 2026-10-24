const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');

let _db;
const db = () => (_db = _db || neon(process.env.DATABASE_URL));
const sql = (...a) => db()(...a);
const SEC = process.env.SESSION_SECRET || '';
const dig = s => crypto.createHash('sha256').update(String(s)).digest();
const sign = t => crypto.createHmac('sha256', SEC).update(t).digest('hex');
const uid = () => crypto.randomBytes(6).toString('hex');
const wait = ms => new Promise(r => setTimeout(r, ms));
const scrypt = (p, salt) => new Promise((ok, no) => crypto.scrypt(String(p), salt, 32, (e, k) => (e ? no(e) : ok(k))));
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);
const bad = (res, e, c = 400) => res.status(c).json({ e });

// ---- permisos: cada permiso = una pantalla del sistema
const PALL = ['inicio', 'venta', 'alq', 'fac', 'cob', 'gas', 'mant', 'poli', 'com', 'asis', 'pag', 'caja', 'ajc', 'graf', 'rep', 'aj', 'stock', 'stkreg', 'stkadj'];
// permiso que exige cada tipo de registro
const TP = { ventas: 'venta', alq: 'alq', abo: 'cob', gas: 'gas', mant: 'mant', poli: 'poli', com: 'com', asis: 'asis', pagos: 'pag', fac: 'fac', caja: 'ajc', stk: 'stkreg' };
// campos que se pueden modificar después de creado un registro
const ALLOW = { ventas: ['cob', 'est'], alq: ['cob', 'est'], asis: ['e', 's', 'h', 'pag', 'd', 'a'], gas: [], mant: [], pagos: [], poli: [], com: [], abo: [], fac: [], caja: [], stk: [] };
const can = (u, p) => !!u && (u.rol === 'admin' || (u.perms || []).includes(p));
const cleanPerms = a => (Array.isArray(a) ? [...new Set(a.filter(x => PALL.includes(x)))] : []);
const pub = u => ({ id: u.id, u: u.u, nom: u.nom, rol: u.rol, perms: u.rol === 'admin' ? PALL : u.perms || [] });

// ---- usuarios (guardados en config 'users', contraseñas cifradas con scrypt)
async function mk(u, nom, rol, perms, p) {
  const s = crypto.randomBytes(16);
  return { id: uid(), u, nom, rol, perms, s: s.toString('hex'), h: (await scrypt(p, s)).toString('hex'), creado: new Date().toISOString() };
}
async function getUsers() {
  const r = await sql`select v from config where k='users'`;
  if (r.length) return r[0].v;
  const L = [
    await mk('admin', 'Administrador', 'admin', PALL, 'admin'),
    await mk('ernesto', 'Ernesto', 'stock', ['stkreg'], '12345678'),
    await mk('chate', 'Chate', 'stock', ['stkreg'], '12345678')
  ];
  await sql`insert into config(k,v) values('users', ${JSON.stringify(L)}::jsonb) on conflict (k) do nothing`;
  return (await sql`select v from config where k='users'`)[0].v;
}
const saveUsers = L => sql`insert into config(k,v) values('users', ${JSON.stringify(L)}::jsonb) on conflict (k) do update set v = excluded.v`;
async function getRoles() {
  const r = await sql`select v from config where k='roles'`;
  return r.length ? r[0].v : [];
}
const saveRoles = L => sql`insert into config(k,v) values('roles', ${JSON.stringify(L)}::jsonb) on conflict (k) do update set v = excluded.v`;
const passOk = async (p, x) => !!x && eq(await scrypt(String(p || ''), Buffer.from(x.s, 'hex')), Buffer.from(x.h, 'hex'));
async function newCred(p) {
  const s = crypto.randomBytes(16);
  return { s: s.toString('hex'), h: (await scrypt(p, s)).toString('hex') };
}

// ---- contraseñas de la zona "Borrar datos por mes" (A = borrar, B = maestra para cambiarlas)
const getBor = async () => { const r = await sql`select v from config where k='borrado'`; return r.length ? r[0].v : null; };
async function borChk(p, slot, cfg) {
  p = String(p || '');
  if (cfg && cfg[slot]) return eq(await scrypt(p, Buffer.from(cfg[slot].s, 'hex')), Buffer.from(cfg[slot].h, 'hex'));
  return eq(dig(p), dig(slot === 'a' ? 'Jeffry' : '03062025'));
}

// ---- sesión: cookie = vence.idUsuario.firma
async function sesion(req) {
  const m = (req.headers.cookie || '').match(/fc=([^;]+)/);
  if (!m || !SEC) return null;
  const [e, id, g] = m[1].split('.');
  if (!e || !id || !g || Date.now() > +e) return null;
  if (!eq(Buffer.from(sign(e + '.' + id)), Buffer.from(g))) return null;
  return (await getUsers()).find(x => x.id === id) || null;
}
const aud = accion => sql`insert into auditoria(accion) values(${accion})`;
const MULT = { Palas: 'pala', Metros: 'metro', Volquetes: 'volq' };

module.exports = async (req, res) => {
  try {
    // Ver foto de un recibo
    if (req.method === 'GET') {
      const me = await sesion(req);
      if (!me || !['gas', 'mant', 'rep', 'inicio', 'graf'].some(p => can(me, p))) return res.status(401).end();
      const r = await sql`select img from fotos where id=${String(req.query.id || '')}`;
      if (!r.length) return res.status(404).end();
      const m = r[0].img.match(/^data:(.+?);base64,(.+)$/);
      res.setHeader('Content-Type', m[1]);
      res.setHeader('Cache-Control', 'private, max-age=86400');
      return res.send(Buffer.from(m[2], 'base64'));
    }
    const b = req.body || {};

    if (b.a === 'login') {
      if (!SEC) return bad(res, 'Falta la variable SESSION_SECRET en Vercel. Agrégala y haz Redeploy.', 500);
      const us = await getUsers(), u = String(b.u || '').trim().toLowerCase(), x = us.find(z => z.u === u);
      const ok = x ? await passOk(b.p, x) : (await scrypt('x', Buffer.alloc(16)), false);
      if (!ok) { await wait(900); return bad(res, 'Usuario o contraseña incorrectos', 401); }
      const e = String(Date.now() + 12 * 3600e3);
      res.setHeader('Set-Cookie', `fc=${e}.${x.id}.${sign(e + '.' + x.id)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`);
      await aud(`[${x.u}] Ingreso al sistema`);
      return res.json({ ok: 1 });
    }
    if (b.a === 'logout') {
      res.setHeader('Set-Cookie', 'fc=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
      return res.json({ ok: 1 });
    }
    const me = await sesion(req);
    if (!me) return bad(res, 'auth', 401);
    const A = x => aud(`[${me.u}] ${x}`);
    const need = p => { if (can(me, p)) return true; bad(res, 'No tienes permiso para hacer esto', 403); return false; };
    const adminOk = async () => {
      if (me.rol !== 'admin') { bad(res, 'Solo el administrador puede hacer esto', 403); return false; }
      if (!(await passOk(b.ap, me))) { await wait(900); bad(res, 'Tu contraseña de administrador no es correcta', 403); return false; }
      return true;
    };

    if (b.a === 'all') {
      const full = ['inicio', 'caja', 'graf', 'rep', 'ajc'].some(p => can(me, p));
      const vis = t => full || can(me, TP[t])
        || ((t === 'ventas' || t === 'alq') && (can(me, 'cob') || can(me, 'fac') || (t === 'ventas' && can(me, 'stock'))))
        || (t === 'asis' && can(me, 'pag')) || (t === 'stk' && (can(me, 'stock') || can(me, 'stkadj')));
      const [r, l, t, c] = await Promise.all([
        sql`select id, tipo, f::text as f, data, anu from registros order by creado`,
        me.rol === 'admin' ? sql`select to_char(t at time zone 'America/Lima','YYYY-MM-DD HH24:MI') as t, accion from auditoria order by id desc limit 40` : Promise.resolve([]),
        sql`select to_char(now() at time zone 'America/Lima','YYYY-MM-DD') as f`,
        sql`select v from config where k='cfg'`
      ]);
      let cfg = c.length ? c[0].v : {};
      if (me.rol !== 'admin') {
        cfg = { ...cfg };
        if (!['aj', 'venta', 'stock', 'inicio', 'rep', 'fac', 'graf'].some(p => can(me, p))) {
          if (Array.isArray(cfg.mats)) cfg.mats = cfg.mats.map(m => ({ n: m.n }));
          if (Array.isArray(cfg.ral)) cfg.ral = cfg.ral.map(m => ({ n: m.n, p: 0 }));
        }
        if (!['aj', 'pag'].some(p => can(me, p)) && Array.isArray(cfg.sue)) cfg.sue = cfg.sue.map(() => 0);
      }
      const out = { cfg: { cfg }, regs: r.filter(x => vis(x.tipo)), log: l, hoy: t[0].f, me: pub(me) };
      if (me.rol === 'admin') {
        out.users = (await getUsers()).map(x => ({ id: x.id, u: x.u, nom: x.nom, rol: x.rol, perms: x.perms, creado: x.creado }));
        out.roles = await getRoles();
      }
      return res.json(out);
    }

    // ---------- Usuarios y roles (solo administrador, siempre con su contraseña)
    if (b.a === 'usr_add') {
      if (!(await adminOk())) return;
      const us = await getUsers(), roles = await getRoles();
      const nom = String(b.nom || '').trim().slice(0, 60), u = String(b.u || '').trim().toLowerCase(), p = String(b.p || '');
      if (u.length < 3 || /\s/.test(u)) return bad(res, 'El usuario debe tener al menos 3 caracteres y no llevar espacios');
      if (p.length < 4) return bad(res, 'La contraseña debe tener al menos 4 caracteres');
      if (us.some(x => x.u === u)) return bad(res, 'Ese usuario ya existe');
      let rol = String(b.rol || ''), perms = cleanPerms(b.perms);
      if (rol === 'admin') perms = [...PALL];
      else if (rol === 'stock') { if (!perms.length) perms = ['stkreg']; }
      else if (rol === 'otro') {
        const rn = String(b.rn || '').trim().slice(0, 40);
        if (rn.length < 2 || ['admin', 'stock', 'otro'].includes(rn.toLowerCase())) return bad(res, 'Escribe un nombre válido para el nuevo rol');
        if (!perms.length) return bad(res, 'Elige al menos un permiso para el nuevo rol');
        const i = roles.findIndex(r => r.n.toLowerCase() === rn.toLowerCase());
        if (i < 0) roles.push({ n: rn, perms }); else roles[i].perms = perms;
        await saveRoles(roles);
        rol = rn;
      } else {
        if (!roles.some(r => r.n === rol)) return bad(res, 'Rol inválido');
        if (!perms.length) return bad(res, 'Elige al menos un permiso');
      }
      const nu = await mk(u, nom || u, rol, perms, p);
      us.push(nu);
      await saveUsers(us);
      await A(`Usuario creado: ${u} (${rol})`);
      return res.json({ id: nu.id });
    }
    if (b.a === 'usr_del') {
      if (!(await adminOk())) return;
      const us = await getUsers(), x = us.find(z => z.id === String(b.id));
      if (!x) return bad(res, 'No existe ese usuario', 404);
      if (x.id === me.id) return bad(res, 'No puedes eliminar tu propio usuario');
      if (x.rol === 'admin' && us.filter(z => z.rol === 'admin').length <= 1) return bad(res, 'Debe quedar al menos un administrador');
      await saveUsers(us.filter(z => z.id !== x.id));
      await A(`Usuario eliminado: ${x.u}`);
      return res.json({ ok: 1 });
    }
    if (b.a === 'usr_perm') {
      if (!(await adminOk())) return;
      const us = await getUsers(), x = us.find(z => z.id === String(b.id));
      if (!x) return bad(res, 'No existe ese usuario', 404);
      if (x.rol === 'admin') return bad(res, 'El administrador siempre tiene acceso a todo');
      const perms = cleanPerms(b.perms);
      if (!perms.length) return bad(res, 'Elige al menos un permiso');
      x.perms = perms;
      await saveUsers(us);
      await A(`Permisos cambiados a ${x.u}: ${perms.join(',')}`);
      return res.json({ ok: 1 });
    }
    if (b.a === 'usr_pass') {
      if (!(await adminOk())) return;
      const us = await getUsers(), x = us.find(z => z.id === String(b.id)), np = String(b.np || '');
      if (!x) return bad(res, 'No existe ese usuario', 404);
      if (np.length < 4) return bad(res, 'La contraseña debe tener al menos 4 caracteres');
      Object.assign(x, await newCred(np));
      await saveUsers(us);
      await A(`Contraseña cambiada a ${x.u}`);
      return res.json({ ok: 1 });
    }
    if (b.a === 'rol_del') {
      if (!(await adminOk())) return;
      const us = await getUsers(), roles = await getRoles(), n = String(b.n || '');
      if (us.some(x => x.rol === n)) return bad(res, 'Hay usuarios con ese rol. Cámbiales los permisos o elimínalos primero');
      await saveRoles(roles.filter(r => r.n !== n));
      await A(`Rol eliminado: ${n}`);
      return res.json({ ok: 1 });
    }

    // Cambiar usuario y/o contraseña del administrador
    if (b.a === 'cred') {
      if (me.rol !== 'admin') return bad(res, 'Solo el administrador puede cambiar contraseñas', 403);
      const nu = String(b.nu || '').trim().toLowerCase(), np = String(b.np || '');
      if (!nu && !np) return bad(res, 'No hay nada que cambiar');
      if (nu && nu.length < 3) return bad(res, 'El usuario debe tener al menos 3 caracteres');
      if (np && np.length < 6) return bad(res, 'La contraseña debe tener al menos 6 caracteres');
      if (!(await passOk(b.p, me))) { await wait(900); return bad(res, 'La contraseña actual no es correcta', 403); }
      const us = await getUsers(), x = us.find(z => z.id === me.id);
      if (nu && us.some(z => z.u === nu && z.id !== me.id)) return bad(res, 'Ese usuario ya existe');
      if (nu) x.u = nu;
      if (np) Object.assign(x, await newCred(np));
      await saveUsers(us);
      await A('Cambio de ' + [nu && 'usuario', np && 'contraseña'].filter(Boolean).join(' y '));
      return res.json({ ok: 1 });
    }

    // ---------- Borrar datos por mes (solo administrador + contraseña propia de esta zona)
    if (b.a === 'bor_auth') {
      if (me.rol !== 'admin') return bad(res, 'Solo el administrador', 403);
      const cfg = await getBor();
      if (await borChk(b.p, 'a', cfg)) return res.json({ m: 'a' });
      if (await borChk(b.p, 'b', cfg)) return res.json({ m: 'b' });
      await wait(900);
      return bad(res, 'Contraseña incorrecta', 403);
    }
    if (b.a === 'bor_cambiar') {
      if (me.rol !== 'admin') return bad(res, 'Solo el administrador', 403);
      const cfg = await getBor();
      if (!(await borChk(b.p, 'b', cfg))) { await wait(900); return bad(res, 'Contraseña incorrecta', 403); }
      const na = String(b.na || ''), nb = String(b.nb || '');
      if (!na && !nb) return bad(res, 'Escribe al menos una contraseña nueva');
      if ((na && na.length < 4) || (nb && nb.length < 4)) return bad(res, 'Cada contraseña debe tener al menos 4 caracteres');
      const nuevo = {
        a: na ? await newCred(na) : (cfg && cfg.a) || await newCred('Jeffry'),
        b: nb ? await newCred(nb) : (cfg && cfg.b) || await newCred('03062025')
      };
      await sql`insert into config(k,v) values('borrado', ${JSON.stringify(nuevo)}::jsonb) on conflict (k) do update set v = excluded.v`;
      await A('Cambio de contraseñas de la zona de borrado');
      return res.json({ ok: 1 });
    }
    if (b.a === 'borrar') {
      if (me.rol !== 'admin') return bad(res, 'Solo el administrador', 403);
      if (!(await borChk(b.p, 'a', await getBor()))) { await wait(900); return bad(res, 'Contraseña incorrecta', 403); }
      const mes = String(b.mes || '');
      if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(mes)) return bad(res, 'Elige el mes');
      const tipos = (Array.isArray(b.tipos) ? b.tipos : []).filter(t => Object.prototype.hasOwnProperty.call(TP, t));
      if (!tipos.length) return bad(res, 'Elige qué apartados borrar');
      const a = mes + '-01', z = new Date(+mes.slice(0, 4), +mes.slice(5, 7), 0).getDate(), f2 = mes + '-' + String(z).padStart(2, '0'), lst = tipos.join(',');
      const q = db();
      const rr = await q.transaction([
        q`select set_config('app.borrar','1',true)`,
        q`delete from fotos where id in (select id from registros where f>=${a}::date and f<=${f2}::date and tipo = any(string_to_array(${lst}, ',')))`,
        q`delete from registros where f>=${a}::date and f<=${f2}::date and tipo = any(string_to_array(${lst}, ',')) returning id`,
        q`insert into auditoria(accion) values(${`[${me.u}] BORRADO ${mes}: ${lst}`})`
      ]);
      return res.json({ n: rr[2].length });
    }

    if (b.a === 'cfg') {
      if (!need('aj')) return;
      await sql`insert into config(k,v) values('cfg', ${JSON.stringify(b.cfg || {})}::jsonb)
                on conflict (k) do update set v = excluded.v`;
      let acc = 'Configuración actualizada';
      if (Array.isArray(b.ren) && b.ren.length === 2) {
        await sql`update registros set data = jsonb_set(data,'{c}', to_jsonb(${String(b.ren[1])}::text)) where data->>'c' = ${String(b.ren[0])}`;
        acc += ` · ${b.ren[0]} → ${b.ren[1]}`;
      }
      await A(acc);
      return res.json({ ok: 1 });
    }

    // Petróleo para varios vehículos a la vez: una sola foto, todo o nada (transacción)
    if (b.a === 'gasmulti') {
      if (!need('gas')) return;
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
      items.push(q`insert into auditoria(accion) values(${`[${me.u}] Alta gas (${ids.length} vehículos) ${ids.join(',')}`})`);
      await q.transaction(items);
      return res.json({ ids });
    }

    // Pasar dinero de una cuenta a otra (salida + entrada, todo o nada)
    if (b.a === 'cajatr') {
      if (!need('ajc')) return;
      const m = +b.mon, from = String(b.from || '').trim(), to = String(b.to || '').trim(), mot = String(b.mot || '').trim(), resp = String(b.resp || '').trim();
      if (!from || !to || from === to) return bad(res, 'Elige dos cuentas distintas');
      if (!(m > 0)) return bad(res, 'Monto inválido');
      if (mot.length < 3 || !resp) return bad(res, 'Falta el motivo o quién lo hizo');
      const [{ f: hoy }] = await sql`select to_char(now() at time zone 'America/Lima','YYYY-MM-DD') as f`;
      const q = db(), a = uid(), c = uid();
      await q.transaction([
        q`insert into registros(id,tipo,f,data) values(${a}, 'caja', ${hoy}, ${JSON.stringify({ cta: from, mon: m, sg: -1, k: 'transf', mot: 'Pasó a ' + to + ': ' + mot, resp })}::jsonb)`,
        q`insert into registros(id,tipo,f,data) values(${c}, 'caja', ${hoy}, ${JSON.stringify({ cta: to, mon: m, sg: 1, k: 'transf', mot: 'Vino de ' + from + ': ' + mot, resp })}::jsonb)`,
        q`insert into auditoria(accion) values(${`[${me.u}] Transferencia entre cuentas ${a},${c}`})`
      ]);
      return res.json({ ids: [a, c] });
    }

    // Factura: el servidor asigna el correlativo (sin saltos) y calcula IGV
    if (b.a === 'facnew') {
      if (!need('fac')) return;
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
          await A(`Alta factura ${ser}-${String(ins[0].num).padStart(8, '0')} ${id}`);
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

      // Stock: lo llena el usuario de stock (solo cantidades) o el administrador (ajuste directo)
      if (t === 'stk') {
        const aj = d.k === 'ajuste';
        if (!need(aj ? 'stkadj' : 'stkreg')) return;
        const mat = String(d.mat || '').trim(), u = String(d.u || ''), q = +d.q;
        if (!['Palas', 'Metros', 'Cúbicos', 'Volquetes'].includes(u)) return bad(res, 'Elige la unidad');
        if (!(q > 0) || q > 100000) return bad(res, 'Cantidad inválida');
        const cf = await sql`select v from config where k='cfg'`, cv = cf.length ? cf[0].v : {};
        if (!mat || (Array.isArray(cv.mats) && !cv.mats.some(m => m.n === mat))) return bad(res, 'Elige un material registrado');
        const EQ = Object.assign({ pala: 3, metro: 1, volq: 10 }, cv.eq || {});
        const rec = { mat, u, q, m3: Math.round(q * (MULT[u] ? +EQ[MULT[u]] || 1 : 1) * 100) / 100, sg: aj && +d.sg === -1 ? -1 : 1, k: aj ? 'ajuste' : 'ingreso', by: me.nom || me.u, h };
        if (aj) {
          const mot = String(d.mot || '').trim();
          if (mot.length < 3) return bad(res, 'Escribe el motivo del ajuste');
          rec.mot = mot.slice(0, 200);
        }
        const id = uid();
        await sql`insert into registros(id,tipo,f,data) values(${id}, 'stk', ${hoy}, ${JSON.stringify(rec)}::jsonb)`;
        await A(`Stock ${rec.sg > 0 ? '+' : '−'}${q} ${u} de ${mat} (${rec.k}) ${id}`);
        return res.json({ id });
      }

      if (!need(TP[t])) return;
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
      await A(`Alta ${t} ${id}`);
      return res.json({ id });
    }

    if (b.a === 'upd') {
      const r = (await sql`select tipo, data, anu from registros where id=${String(b.id)}`)[0];
      if (!r) return bad(res, 'No existe', 404);
      const okp = r.tipo === 'ventas' || r.tipo === 'alq' ? (can(me, 'cob') || can(me, TP[r.tipo])) : r.tipo === 'asis' ? (can(me, 'asis') || can(me, 'pag')) : can(me, TP[r.tipo]);
      if (!okp) return bad(res, 'No tienes permiso para hacer esto', 403);
      if (r.anu) return bad(res, 'Registro anulado');
      const p = {};
      for (const k of ALLOW[r.tipo]) if (b.patch && k in b.patch) p[k] = b.patch[k];
      if (r.tipo === 'asis' && r.data.pag && 'h' in p && +p.h !== +r.data.h) return bad(res, 'Horas extra ya pagadas');
      await sql`update registros set data=${JSON.stringify({ ...r.data, ...p })}::jsonb where id=${String(b.id)}`;
      await A(`Modificación ${r.tipo} ${b.id}: ${Object.keys(p).join(',')}`);
      return res.json({ ok: 1 });
    }

    if (b.a === 'anu') {
      if (!b.m || String(b.m).trim().length < 3) return bad(res, 'Motivo obligatorio');
      const r0 = (await sql`select tipo from registros where id=${String(b.id)}`)[0];
      if (!r0) return bad(res, 'No existe', 404);
      if (!can(me, r0.tipo === 'stk' ? 'stkadj' : TP[r0.tipo])) return bad(res, 'No tienes permiso para hacer esto', 403);
      const r = await sql`update registros set anu=${JSON.stringify({ m: String(b.m), t: new Date().toISOString() })}::jsonb
                          where id=${String(b.id)} and anu is null and tipo<>'asis' returning id`;
      if (!r.length) return bad(res, 'No se puede anular');
      await A(`Anulado ${b.id}: ${b.m}`);
      return res.json({ ok: 1 });
    }
    return bad(res, 'Acción desconocida');
  } catch (e) {
    return res.status(500).json({ e: 'Error del servidor: ' + e.message });
  }
};
