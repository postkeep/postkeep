-- The storage level: how new the stored formats are. A version refuses to start
-- on a database recorded above the level it reads. One row, only_row always 1.
-- It starts at 1, the formats of this version: values under the master key
-- (v1.) and under a tenant's data key (v2.).
CREATE TABLE storage_level (
    only_row BIGINT NOT NULL PRIMARY KEY CHECK (only_row = 1),
    level BIGINT NOT NULL CHECK (level >= 0)
);

INSERT INTO storage_level (only_row, level) VALUES (1, 1);
