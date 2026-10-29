-- Esquema para la Plataforma de Derivación a Convivencia Escolar.
-- Ejecutar completo en Supabase > SQL Editor.

-- ---------- Perfiles de funcionarios ----------
create table if not exists public.profiles (
  id        uuid primary key references auth.users(id) on delete cascade,
  email     text,
  nombre    text not null,
  cargo     text,
  aprobado  boolean not null default false,
  es_admin  boolean not null default false,
  creado    timestamptz not null default now()
);

-- ---------- Almacén clave/valor (derivaciones, atenciones, contadores, config) ----------
create table if not exists public.kv (
  key         text primary key,
  value       text not null,
  creado_por  uuid default auth.uid(),
  actualizado timestamptz not null default now()
);

-- ---------- Funciones auxiliares (security definer evita recursión de RLS) ----------
create or replace function public.es_aprobado() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select aprobado from public.profiles where id = auth.uid()), false);
$$;

create or replace function public.es_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select aprobado and es_admin from public.profiles where id = auth.uid()), false);
$$;

-- Crea el perfil (pendiente de aprobación) cuando alguien se registra.
create or replace function public.crear_perfil() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, nombre, cargo)
  values (
    new.id,
    new.email,
    coalesce(nullif(new.raw_user_meta_data->>'nombre', ''), new.email),
    new.raw_user_meta_data->>'cargo'
  );
  return new;
end;
$$;

drop trigger if exists al_crear_usuario on auth.users;
create trigger al_crear_usuario after insert on auth.users
  for each row execute function public.crear_perfil();

-- Folio correlativo atómico: evita que dos funcionarios reciban el mismo número.
create or replace function public.siguiente_folio(clave text) returns integer
language plpgsql security definer set search_path = public as $$
declare n integer;
begin
  if not public.es_aprobado() then
    raise exception 'No autorizado';
  end if;
  insert into public.kv (key, value) values (clave, '1')
  on conflict (key) do update
    set value = ((public.kv.value)::integer + 1)::text, actualizado = now()
  returning (value)::integer into n;
  return n;
end;
$$;

-- ---------- Seguridad por fila ----------
alter table public.profiles enable row level security;
alter table public.kv       enable row level security;

drop policy if exists "perfil propio o admin" on public.profiles;
create policy "perfil propio o admin" on public.profiles
  for select to authenticated
  using (id = auth.uid() or public.es_admin());

-- Solo un administrador aprobado puede aprobar cuentas o dar permisos.
drop policy if exists "admin gestiona perfiles" on public.profiles;
create policy "admin gestiona perfiles" on public.profiles
  for update to authenticated
  using (public.es_admin()) with check (public.es_admin());

drop policy if exists "funcionarios leen" on public.kv;
create policy "funcionarios leen" on public.kv
  for select to authenticated using (public.es_aprobado());

drop policy if exists "funcionarios insertan" on public.kv;
create policy "funcionarios insertan" on public.kv
  for insert to authenticated with check (public.es_aprobado());

drop policy if exists "funcionarios actualizan" on public.kv;
create policy "funcionarios actualizan" on public.kv
  for update to authenticated
  using (public.es_aprobado()) with check (public.es_aprobado());

-- Nadie borra registros desde la app (no hay política de delete).

grant execute on function public.siguiente_folio(text) to authenticated;

-- ---------- Primer administrador ----------
-- 1) Crea tu cuenta desde la plataforma.
-- 2) Ejecuta esto con tu correo para aprobarte como administrador:
--
--   update public.profiles set aprobado = true, es_admin = true
--   where email = 'tu-correo@ejemplo.cl';
