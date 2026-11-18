const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const db = new Database("friendshub.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contributions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL,
    amount REAL NOT NULL CHECK(amount > 0),
    purpose TEXT NOT NULL,
    contribution_date TEXT NOT NULL,
    notes TEXT,
    FOREIGN KEY(member_id) REFERENCES members(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    activity_date TEXT NOT NULL,
    status TEXT DEFAULT 'Planned'
);
`);

const admins = [
    {
        name: process.env.ADMIN1_NAME,
        email: process.env.ADMIN1_EMAIL,
        password: process.env.ADMIN1_PASSWORD
    },
    {
        name: process.env.ADMIN2_NAME,
        email: process.env.ADMIN2_EMAIL,
        password: process.env.ADMIN2_PASSWORD
    }
];

const count = db.prepare("SELECT COUNT(*) AS total FROM admins").get().total;

if (count === 0) {
    for (const admin of admins) {
        if (!admin.name || !admin.email ||
            !admin.password || admin.password.length < 12) {
            throw new Error("Configure both admins with passwords of at least 12 characters.");
        }

        db.prepare(`
            INSERT INTO admins (name, email, password)
            VALUES (?, ?, ?)
        `).run(
            admin.name,
            admin.email.toLowerCase(),
            bcrypt.hashSync(admin.password, 12)
        );
    }
}

if (count !== 0 && count !== 2) {
    throw new Error("The database must contain exactly two administrators.");
}

module.exports = db;