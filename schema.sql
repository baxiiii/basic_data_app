PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS maintenance_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    priority TEXT NOT NULL,
    status TEXT NOT NULL,
    user_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS inspection_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    maintenance_log_id INTEGER NOT NULL,
    item_number TEXT NOT NULL,
    description TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('pass', 'fail', 'na')),
    notes TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (maintenance_log_id) REFERENCES maintenance_logs(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS maintenance_log_media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    maintenance_log_id INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    file_name TEXT,
    file_path TEXT,
    media_blob BLOB,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (maintenance_log_id) REFERENCES maintenance_logs(id) ON DELETE CASCADE,
    CHECK (media_type IN ('image', 'video')),
    CHECK (
        (file_path IS NOT NULL AND media_blob IS NULL)
        OR (file_path IS NULL AND media_blob IS NOT NULL)
    )
);

INSERT INTO inspection_items (maintenance_log_id, item_number, description, result, notes)
VALUES (1, 'A320-HYD-001', 'Check hydraulic fluid level', 'pass', 'Fluid level normal');