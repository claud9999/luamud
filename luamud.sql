create table mud_obj(id, par_id, loc_id);
create table mud_prop(obj_id, name, val);

insert into mud_obj(id, par_id, loc_id) values(0, 0, 0);
insert into mud_prop(obj_id, name, val) values(0, "name", "root");
