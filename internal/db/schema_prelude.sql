-- Read by sqlc only, never run. The auth schema is created by auth.Migrate
-- before the migrations run, so sqlc needs to be told it exists.
CREATE SCHEMA auth;
