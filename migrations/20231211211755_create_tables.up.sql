-- Add up migration script here
-- Add migration script here
-- Add up migration script here
-- Add migration script here
start transaction;

create table if not exists users(
    id uuid primary key not null default gen_random_uuid(),
	github_id integer not null unique,
	username varchar not null unique,
	display_name varchar,
	email varchar not null unique,
	bio varchar,
	avatar varchar,
	banner varchar,
	permissions integer not null default 0,
	api_key uuid not null unique default gen_random_uuid(),
	created_at timestamp not null default now(),
	updated_at timestamp not null default now()
);

create table if not exists categories(
	id uuid primary key not null default gen_random_uuid(),
	name varchar not null unique,
	description varchar not null unique
);

create table if not exists mod_stats(
	id uuid primary key not null default gen_random_uuid(),
	downloads integer not null default 0
);

create table if not exists version_stats(
	id uuid primary key not null default gen_random_uuid(),
	downloads integer not null default 0
);

create table if not exists beat_saber_versions(
	id uuid primary key not null default gen_random_uuid(),
	ver varchar not null unique
);

create table if not exists mods(
	id uuid primary key not null default gen_random_uuid(),
	slug varchar not null unique,
	name varchar not null,
	description varchar not null,
	icon varchar not null,
	cover varchar not null,
	author uuid not null references users(id) on update cascade on delete cascade,
	category uuid not null references categories(id) on update cascade on delete cascade,
	stats uuid not null unique references mod_stats(id) on update cascade on delete cascade,
	website varchar,
	created_at timestamp not null default now(),
	updated_at timestamp not null default now()
);

create table if not exists versions(
	id uuid primary key not null default gen_random_uuid(),
	mod_id uuid not null references mods(id) on update cascade on delete cascade,
	version varchar not null,
	approved boolean not null default false,
	stats uuid not null unique references version_stats(id) on update cascade on delete cascade,
	artifact_hash varchar not null,
	download_url varchar not null,
	created_at timestamp not null default now()
);

create table if not exists version_dependents(
	version_id uuid not null references versions(id) on update cascade on delete cascade,
	dependent uuid not null references versions(id) on update cascade on delete cascade
);

create table if not exists version_conflicts(
	version_id uuid not null references versions(id) on update cascade on delete cascade,
	dependent uuid not null references versions(id) on update cascade on delete cascade
);

create table if not exists mod_versions(
	mod_id uuid not null references mods(id) on update cascade on delete cascade,
	version_id uuid not null references versions(id) on update cascade on delete cascade
);

create table if not exists user_mods(
	user_id uuid not null references users(id) on update cascade on delete cascade,
	mod_id uuid not null references mods(id) on update cascade on delete cascade
);

create table if not exists version_beat_saber_versions(
	version_id uuid not null references versions(id) on update cascade on delete cascade,
	beat_saber_version_id uuid not null references beat_saber_versions(id) on update cascade on delete cascade
);

create table if not exists mod_beat_saber_versions(
    mod_id uuid not null references mods(id) on update cascade on delete cascade,
    beat_saber_version_id uuid not null references beat_saber_versions(id) on update cascade on delete cascade
);

create table if not exists _meilisearch_migrations(
	id uuid primary key not null default gen_random_uuid(),
	name varchar not null unique,
	created_at timestamp not null default now()
);

commit;