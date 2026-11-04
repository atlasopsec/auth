-- Wrong 2FA codes from a device where a code was entered before count
-- toward a guessing limit of that device's own, so someone who has the
-- password can't pause 2FA for the owner's usual browser or phone. See
-- docs/api.md §8.

-- +goose Up
SET lock_timeout = '5s';

-- The device token's failure key ("device:<id>"), or NULL for the
-- account-wide count. A nullable column with no default, so adding it
-- changes no rows. The table only holds the last 15 minutes of wrong
-- codes, so checking the constraint is quick.
ALTER TABLE auth.two_factor_failures
    ADD COLUMN device_key text CONSTRAINT two_factor_failures_device_key_max_length CHECK (length(device_key) <= 200);

-- A plain SET outlasts the transaction, and Migrate runs on the project's
-- pool, so put the setting back before the connection returns to it.
RESET lock_timeout;

-- +goose Down
ALTER TABLE auth.two_factor_failures DROP COLUMN device_key;
