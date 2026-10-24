-- FERROCONTROL · pega TODO esto en Neon > SQL Editor > Run
-- Se puede ejecutar las veces que quieras: no borra ni duplica nada.

create table if not exists config (
  k text primary key,
  v jsonb not null
);

-- Todos los movimientos: ventas, alquileres, cobros, gasolina, mantenimiento, policía, comidas, asistencia, pagos, facturas y movimientos de caja
create table if not exists registros (
  id text primary key,
  tipo text not null,
  f date not null,                       -- fecha del movimiento (hora de Lima)
  data jsonb not null,                   -- detalle del movimiento
  anu jsonb,                             -- si fue anulado: motivo y fecha
  creado timestamptz not null default now()
);
create index if not exists registros_tipo_f on registros (tipo, f);

-- IMPORTANTE: la versión anterior solo permitía 5 tipos y la base rechazaba
-- alquileres, cobros, policía y comidas. Esto reemplaza esa regla por la correcta.
do $$
declare c record;
begin
  for c in select conname from pg_constraint
           where conrelid = 'registros'::regclass and contype = 'c'
             and pg_get_constraintdef(oid) ilike '%tipo%'
  loop
    execute format('alter table registros drop constraint %I', c.conname);
  end loop;
  alter table registros add constraint registros_tipo_check
    check (tipo in ('ventas','alq','abo','gas','mant','poli','com','asis','pagos','fac','caja'));
end $$;

-- Facturas: nunca puede repetirse una serie + número (correlativo sin saltos ni duplicados)
create unique index if not exists fac_serie_num on registros ((data->>'ser'), ((data->>'num')::int)) where tipo = 'fac';

-- Fotos de recibos (gasolina y mantenimiento)
create table if not exists fotos (
  id text primary key references registros(id),
  img text not null
);

-- Registro de auditoría (quién hizo qué y cuándo)
create table if not exists auditoria (
  id bigserial primary key,
  t timestamptz not null default now(),
  accion text not null
);

-- Nada se borra: la base rechaza cualquier DELETE
create or replace function no_borrar() returns trigger as $$
begin raise exception 'Prohibido borrar registros: use anulación con motivo'; end;
$$ language plpgsql;

drop trigger if exists no_borrar_registros on registros;
create trigger no_borrar_registros before delete on registros for each row execute function no_borrar();
drop trigger if exists no_borrar_fotos on fotos;
create trigger no_borrar_fotos before delete on fotos for each row execute function no_borrar();
drop trigger if exists no_borrar_aud on auditoria;
create trigger no_borrar_aud before delete on auditoria for each row execute function no_borrar();
