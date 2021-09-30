SELECT * FROM pg_catalog.pg_tables;

create database ssh_stats_dev WITH OWNER "ssh_stats_admin" ENCODING 'UTF8' LC_COLLATE = 'en_US.UTF-8' LC_CTYPE = 'en_US.UTF-8' TEMPLATE template0;
create database ssh_stats_test WITH OWNER "ssh_stats_admin" ENCODING 'UTF8' LC_COLLATE = 'en_US.UTF-8' LC_CTYPE = 'en_US.UTF-8' TEMPLATE template0;
create database ssh_stats_prod WITH OWNER "ssh_stats_admin" ENCODING 'UTF8' LC_COLLATE = 'en_US.UTF-8' LC_CTYPE = 'en_US.UTF-8' TEMPLATE template0;

create user ssh_stats_admin with encrypted password '33*33=1089';

create schema ssh_stats authorization ssh_stats_admin;

grant select,insert,update,delete on database ssh_stats_dev to ssh_stats_admin;
grant select,insert,update,delete on database ssh_stats_test to ssh_stats_admin;
grant select,insert,update on database ssh_stats_prod to ssh_stats_admin;
