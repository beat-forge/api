-- Add down migration script here
start transaction;

delete from beat_saber_versions;
delete from categories;

commit;