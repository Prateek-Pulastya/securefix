// Node's built-in SQLite (Node >= 22.5; usable without a flag on Node 24). Zero native
// deps, no build tools. Loaded via createRequire so bundlers/test runners (Vite/Vitest)
// don't try to statically resolve the `node:sqlite` specifier.
// API mirrors better-sqlite3: db.prepare(sql).all(...params) — swap freely later.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');

// In-memory DB, re-seeded every process start. No file, no cleanup.
export const db = new DatabaseSync(':memory:');

db.exec(`
  CREATE TABLE users (
    id       INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL          -- bcrypt-style hash; the SQLi UNION target
  );

  CREATE TABLE invoices (
    id          INTEGER PRIMARY KEY,
    owner_id    INTEGER NOT NULL,   -- used by the IDOR fix (class #2)
    description TEXT NOT NULL,
    amount      REAL NOT NULL,
    note        TEXT DEFAULT ''     -- stored-XSS target (class #4)
  );

  INSERT INTO users (id, username, password) VALUES
    (1, 'alice', '$2b$10$Q9k1sJ0oXfakehashalicexxxxxxxxxxxxxxxxxxxxxxxx'),
    (2, 'bob',   '$2b$10$Z2m4tK1pYfakehashbobxxxxxxxxxxxxxxxxxxxxxxxxxx');

  INSERT INTO invoices (id, owner_id, description, amount) VALUES
    (1, 1, 'Cloud hosting - August',   420.00),
    (2, 1, 'Domain renewal',            15.00),
    (3, 2, 'Pentest engagement',      3200.00);
`);
