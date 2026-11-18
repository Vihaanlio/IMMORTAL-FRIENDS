const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const db = require("./database");
require("dotenv").config();

const app = express();

app.use(helmet());
app.use(express.json({ limit: "20kb" }));

app.use(session({
    store: new SQLiteStore({
        db: "sessions.sqlite",
        dir: "."
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 2 * 60 * 60 * 1000
    }
}));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false
});

// Require an authenticated administrator
function adminOnly(req, res, next) {
    if (!req.session.admin) {
        return res.status(401).json({
            error: "Please log in first."
        });
    }
    next();
}

// Protect requests that change data against cross-site requests
function sameOrigin(req, res, next) {
    if (req.get("X-Requested-With") !== "FriendsHub") {
        return res.status(403).json({
            error: "Invalid request."
        });
    }
    next();
}

app.post("/api/login", loginLimiter, async (req, res) => {
    const { email, password } = req.body || {};

    if (typeof email !== "string" ||
        typeof password !== "string") {
        return res.status(400).json({
            error: "Enter your email and password."
        });
    }

    const admin = db.prepare(
        "SELECT * FROM admins WHERE email = ?"
    ).get(email.trim().toLowerCase());

    if (!admin || !await bcrypt.compare(password, admin.password)) {
        return res.status(401).json({
            error: "Incorrect login details."
        });
    }

    req.session.regenerate(err => {
        if (err) {
            return res.status(500).json({
                error: "Login failed."
            });
        }

        req.session.admin = {
            id: admin.id,
            name: admin.name
        };

        res.json({
            success: true,
            name: admin.name
        });
    });
});

app.use("/api", (req, res, next) => {
    if (req.path === "/login") return next();
    adminOnly(req, res, next);
});

app.use("/api", sameOrigin);

app.post("/api/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({
                error: "Could not log out."
            });
        }

        res.clearCookie("connect.sid");
        res.json({ success: true });
    });
});

app.get("/api/me", (req, res) => {
    res.json({
        name: req.session.admin.name
    });
});

// Dashboard statistics
app.get("/api/dashboard", (req, res) => {
    const members = db.prepare(
        "SELECT COUNT(*) AS total FROM members"
    ).get().total;

    const money = db.prepare(
        "SELECT COALESCE(SUM(amount), 0) AS total FROM contributions"
    ).get().total;

    const plans = db.prepare(
        "SELECT COUNT(*) AS total FROM plans WHERE status = 'Planned'"
    ).get().total;

    res.json({ members, money, plans });
});

// Members
app.get("/api/members", (req, res) => {
    res.json(db.prepare(
        "SELECT * FROM members ORDER BY name"
    ).all());
});

app.post("/api/members", (req, res) => {
    const { name, phone, email } = req.body || {};

    if (typeof name !== "string" || !name.trim() ||
        typeof phone !== "string" || !phone.trim() ||
        (email !== undefined && typeof email !== "string")) {
        return res.status(400).json({
            error: "Enter a valid member name and phone number."
        });
    }

    const result = db.prepare(`
        INSERT INTO members (name, phone, email)
        VALUES (?, ?, ?)
    `).run(name.trim(), phone.trim(), (email || "").trim());

    res.json({ success: true, id: result.lastInsertRowid });
});

app.delete("/api/members/:id", (req, res) => {
    const result = db.prepare(
        "DELETE FROM members WHERE id = ?"
    ).run(req.params.id);

    res.json({ success: result.changes > 0 });
});

// Contributions
app.get("/api/contributions", (req, res) => {
    const rows = db.prepare(`
        SELECT contributions.*, members.name AS member_name
        FROM contributions
        JOIN members ON members.id = contributions.member_id
        ORDER BY contribution_date DESC, contributions.id DESC
    `).all();

    res.json(rows);
});

app.post("/api/contributions", (req, res) => {
    const { member_id, amount, purpose, contribution_date, notes } =
        req.body || {};

    const memberId = Number(member_id);
    const money = Number(amount);

    if (!Number.isSafeInteger(memberId) || memberId <= 0 ||
        !Number.isFinite(money) || money <= 0 ||
        money > 100000000 ||
        typeof purpose !== "string" || !purpose.trim() ||
        typeof contribution_date !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(contribution_date)) {
        return res.status(400).json({
            error: "Check the contribution details."
        });
    }

    if (!db.prepare("SELECT id FROM members WHERE id = ?")
        .get(memberId)) {
        return res.status(404).json({
            error: "Member not found."
        });
    }

    const result = db.prepare(`
        INSERT INTO contributions
        (member_id, amount, purpose, contribution_date, notes)
        VALUES (?, ?, ?, ?, ?)
    `).run(
        memberId,
        money,
        purpose.trim(),
        contribution_date,
        typeof notes === "string" ? notes.trim() : ""
    );

    res.json({ success: true, id: result.lastInsertRowid });
});

app.delete("/api/contributions/:id", (req, res) => {
    const result = db.prepare(
        "DELETE FROM contributions WHERE id = ?"
    ).run(req.params.id);

    res.json({ success: result.changes > 0 });
});

// Group plans
app.get("/api/plans", (req, res) => {
    res.json(db.prepare(
        "SELECT * FROM plans ORDER BY activity_date"
    ).all());
});

app.post("/api/plans", (req, res) => {
    const { title, description, activity_date } = req.body || {};

    if (typeof title !== "string" || !title.trim() ||
        typeof activity_date !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(activity_date)) {
        return res.status(400).json({
            error: "Enter a plan title and valid date."
        });
    }

    const result = db.prepare(`
        INSERT INTO plans (title, description, activity_date)
        VALUES (?, ?, ?)
    `).run(
        title.trim(),
        typeof description === "string" ? description.trim() : "",
        activity_date
    );

    res.json({ success: true, id: result.lastInsertRowid });
});

app.patch("/api/plans/:id", (req, res) => {
    const { status } = req.body || {};

    if (!["Planned", "Completed", "Cancelled"].includes(status)) {
        return res.status(400).json({
            error: "Invalid plan status."
        });
    }

    const result = db.prepare(
        "UPDATE plans SET status = ? WHERE id = ?"
    ).run(status, req.params.id);

    res.json({ success: result.changes > 0 });
});

app.delete("/api/plans/:id", (req, res) => {
    const result = db.prepare(
        "DELETE FROM plans WHERE id = ?"
    ).run(req.params.id);

    res.json({ success: result.changes > 0 });
});

// Serve the website
app.use(express.static("public"));

const port = process.env.PORT || 3000;

app.listen(port, () => {
    console.log(`Friends Hub running at http://localhost:${port}`);
});