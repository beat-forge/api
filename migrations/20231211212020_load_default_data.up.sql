-- Add up migration script here on conflict (ver) do nothing
start transaction;

insert into beat_saber_versions (ver) values ('0.10.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.10.2') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.10.2-p1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.11.0-b1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.11.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.11.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.11.2') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.12.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.12.0-p1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.12.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.12.2') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.13.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.13.0-p1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.13.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('0.13.2') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.0.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.0.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.1.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.1.0-p1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.2.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.3.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.4.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.4.2') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.5.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.6.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.6.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.6.2') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.7.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.8.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.9.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.9.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.10.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.11.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.11.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.12.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.12.2') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.13.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.13.2') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.13.4') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.13.5') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.14.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.15.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.16.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.16.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.16.2') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.16.3') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.16.4') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.17.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.17.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.18.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.18.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.18.2') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.18.3') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.19.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.19.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.20.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.21.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.22.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.22.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.23.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.24.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.24.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.25.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.25.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.26.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.27.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.28.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.29.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.29.1') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.29.4') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.30.0') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.30.2') on conflict (ver) do nothing;
insert into beat_saber_versions (ver) values ('1.31.0') on conflict (ver) do nothing;

insert into categories (name, description) values ('core', 'Mods that only depend on other core mods.') on conflict (name) do nothing;
insert into categories (name, description) values ('libraries', 'Mods that are used by other mods.') on conflict (name) do nothing;
insert into categories (name, description) values ('cosmetic', 'Mods that affect the appearance of the game.') on conflict (name) do nothing;
insert into categories (name, description) values ('gameplay', 'Mods that affect gameplay.') on conflict (name) do nothing;
insert into categories (name, description) values ('leaderboards', 'Mods that affect leaderboards.') on conflict (name) do nothing;
insert into categories (name, description) values ('lighting', 'Mods that affect lighting.') on conflict (name) do nothing;
insert into categories (name, description) values ('multiplayer', 'Mods that change online play.') on conflict (name) do nothing;
insert into categories (name, description) values ('accessibility', 'Mods that affect accessibility.') on conflict (name) do nothing;
insert into categories (name, description) values ('practice', 'Mods that are used for practice.') on conflict (name) do nothing;
insert into categories (name, description) values ('streaming', 'Mods that affect live streams.') on conflict (name) do nothing;
insert into categories (name, description) values ('text', 'Mods that change how text is displayed.') on conflict (name) do nothing;
insert into categories (name, description) values ('tweaks', 'Mods that tweak the gameplay experience.') on conflict (name) do nothing;
insert into categories (name, description) values ('ui', 'Mods that affect the ui.') on conflict (name) do nothing;
insert into categories (name, description) values ('other', 'Mods that do not fit into other categories.') on conflict (name) do nothing;

commit;