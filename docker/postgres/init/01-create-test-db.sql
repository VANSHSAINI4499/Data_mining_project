-- Runs once, on first initialisation of the postgres volume (docker-entrypoint-initdb.d).
-- The test database used by `uv run pytest` (CTI_TEST_DATABASE_URL), owned by POSTGRES_USER.
CREATE DATABASE cti_test;
