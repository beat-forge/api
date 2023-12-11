-- Add down migration script here
start transaction;

drop table users;
drop table categories;
drop table mod_stats;
drop table version_stats;
drop table beat_saber_versions;
drop table mods;
drop table versions;
drop table version_dependents;
drop table version_conflicts;
drop table mod_versions;
drop table user_mods;
drop table version_beat_saber_versions;
drop table mod_beat_saber_versions

commit;