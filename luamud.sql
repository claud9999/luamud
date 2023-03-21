drop table if exists mud_obj;
drop table if exists mud_prop;
drop index if exists mud_prop_pk;

create table mud_obj(
    id integer primary key autoincrement,
    par_id references mud_obj(id),
    loc_id references mud_obj(id),
    own_id references mud_obj(id)
);

create table mud_prop(
    obj_id references mud_obj(id),
    name text,
    type integer,
    val
);
create unique index mud_prop_pk on mud_prop(obj_id, name);

create table mud_auth(
    obj_id references mud_obj(id), -- all auths tied to the player obj
    admin integer, -- boolean (...?)
    connected integer, -- boolean (...? socket fd?)
    username text,
    password text,
    password_salt text
    -- cert, TOTP, etc.
);

insert into mud_obj(id, par_id, loc_id, own_id) values(0, 0, 0, 0);
insert into mud_prop(obj_id, name, type, val) values(0, "name", 4, "root");
insert into mud_auth(obj_id, admin, connected, username, password, password_salt) values(0, 1, 1, "root", "cP7ir/uzzBbZ8j3SUKElp5dobgs=", "1234");
