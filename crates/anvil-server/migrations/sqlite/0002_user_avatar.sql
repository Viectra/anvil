-- Add optional sanitized PNG avatar storage for user accounts.
ALTER TABLE users
    ADD COLUMN avatar_png BLOB NULL;
