const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { DatabaseSync } = require("node:sqlite");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_THIS_PIONEERS_FC_SECRET_2026";

app.use(cors());
app.use(express.json({ limit: "10mb" }));

const db = new DatabaseSync(process.env.DB_PATH || "pioneers_fc.db");

db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");

/* =========================
   DATABASE
========================= */

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    display_name TEXT,
    type TEXT DEFAULT 'visitor',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS players (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    number TEXT,
    name TEXT NOT NULL,
    position TEXT,
    bio TEXT DEFAULT '',
    photo TEXT DEFAULT '',
    rating REAL DEFAULT 0,
    vote_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    player_id INTEGER NOT NULL,
    user_id INTEGER,
    score INTEGER NOT NULL CHECK(score >= 1 AND score <= 10),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(player_id) REFERENCES players(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    player_id INTEGER NOT NULL,
    user_id INTEGER,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    approved INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(player_id) REFERENCES players(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS news (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    image TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fixtures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_team TEXT NOT NULL,
    away_team TEXT NOT NULL,
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    venue TEXT DEFAULT '',
    status TEXT DEFAULT 'upcoming',
    home_score INTEGER,
    away_score INTEGER
);

CREATE TABLE IF NOT EXISTS gallery (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    image TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

try {
    db.exec("ALTER TABLE fixtures ADD COLUMN image TEXT DEFAULT ''");
    console.log("Fixture image column added");
} catch (e) {
    if (!String(e.message).includes("duplicate column name")) {
        throw e;
    }
}

/* =========================
   FOUR ADMINISTRATORS
========================= */

const adminAccounts = [
    ["admin1", "Super Administrator", "super_admin"],
    ["admin2", "Content Administrator", "content_admin"],
    ["admin3", "Players Administrator", "players_admin"],
    ["admin4", "Match Administrator", "match_admin"]
];

const defaultPassword = "PioneersFC@2026";

const insertAdmin = db.prepare(`
    INSERT OR IGNORE INTO admins
    (username,password_hash,role,display_name)
    VALUES (?,?,?,?)
`);

for (const [username, displayName, role] of adminAccounts) {
    const hash = bcrypt.hashSync(defaultPassword, 12);
    insertAdmin.run(username, hash, role, displayName);
}

/* =========================
   SAMPLE PLAYERS
========================= */

const playerCount = db.prepare("SELECT COUNT(*) AS count FROM players").get();

if (playerCount.count === 0) {
    const insert = db.prepare(`
        INSERT INTO players(number,name,position,bio,rating,vote_count)
        VALUES(?,?,?,?,?,?)
    `);

    const samplePlayers = [
        ["01", "John Kato", "Goalkeeper", "", 8.4, 1],
        ["04", "Aaron Mbazira", "Defender", "", 8.1, 1],
        ["07", "Francis Nkalubo", "Midfielder", "", 8.7, 1],
        ["10", "Erick Mabonga", "Forward", "", 9.0, 1],
        ["11", "Isaac Emorite", "Forward", "", 8.6, 1],
        ["14", "Jimmy Busulu", "Midfielder", "", 8.3, 1],
        ["17", "Bravin Mwesige", "Defender", "", 8.5, 1],
        ["19", "Micheal Kibedi", "Defender", "", 8.2, 1]
    ];

    for (const p of samplePlayers) insert.run(...p);
}

/* =========================
   AUTHENTICATION
========================= */

function tokenFor(admin) {
    return jwt.sign(
        {
            id: admin.id,
            username: admin.username,
            role: admin.role
        },
        JWT_SECRET,
        { expiresIn: "7d" }
    );
}

function authenticate(req, res, next) {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return res.status(401).json({
            error: "Authentication required"
        });
    }

    try {
        req.admin = jwt.verify(
            header.substring(7),
            JWT_SECRET
        );
        next();
    } catch {
        res.status(401).json({
            error: "Invalid or expired token"
        });
    }
}

function requireRoles(...roles) {
    return (req, res, next) => {
        if (!req.admin || !roles.includes(req.admin.role)) {
            return res.status(403).json({
                error: "Insufficient permissions"
            });
        }

        next();
    };
}

/* =========================
   HEALTH
========================= */

app.get("/api/health", (req, res) => {
    res.json({
        ok: true,
        app: "Pioneers FC",
        version: "1.0",
        database: "SQLite"
    });
});

/* =========================
   ADMIN LOGIN
========================= */

app.post("/api/admin/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            error: "Username and password are required"
        });
    }

    const admin = db.prepare(
        "SELECT * FROM admins WHERE username = ?"
    ).get(username);

    if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
        return res.status(401).json({
            error: "Invalid administrator credentials"
        });
    }

    res.json({
        token: tokenFor(admin),
        admin: {
            id: admin.id,
            username: admin.username,
            role: admin.role,
            displayName: admin.display_name
        }
    });
});

/* =========================
   ADMIN INFORMATION
========================= */

app.get(
    "/api/admin/me",
    authenticate,
    (req, res) => {
        const admin = db.prepare(
            "SELECT id,username,role,display_name FROM admins WHERE id=?"
        ).get(req.admin.id);

        res.json(admin);
    }
);

app.get(
    "/api/admins",
    authenticate,
    requireRoles("super_admin"),
    (req, res) => {
        const admins = db.prepare(`
            SELECT id,username,role,display_name,created_at
            FROM admins
            ORDER BY id
        `).all();

        res.json(admins);
    }
);

/* =========================
   PLAYERS
========================= */

app.get("/api/players", (req, res) => {
    const players = db.prepare(`
        SELECT *
        FROM players
        ORDER BY CAST(number AS INTEGER)
    `).all();

    res.json(players);
});

app.get("/api/players/:id", (req, res) => {
    const player = db.prepare(
        "SELECT * FROM players WHERE id=?"
    ).get(req.params.id);

    if (!player) {
        return res.status(404).json({
            error: "Player not found"
        });
    }

    const reviews = db.prepare(`
        SELECT id,author,body,approved,created_at
        FROM reviews
        WHERE player_id=? AND approved=1
        ORDER BY id DESC
    `).all(req.params.id);

    res.json({
        ...player,
        reviews
    });
});

app.post(
    "/api/players",
    authenticate,
    requireRoles("super_admin", "players_admin"),
    (req, res) => {
        const {
            number,
            name,
            position,
            bio = "",
            photo = ""
        } = req.body;

        if (!name) {
            return res.status(400).json({
                error: "Player name is required"
            });
        }

        const result = db.prepare(`
            INSERT INTO players
            (number,name,position,bio,photo)
            VALUES(?,?,?,?,?)
        `).run(number, name, position, bio, photo);

        res.status(201).json({
            id: result.lastInsertRowid,
            message: "Player created"
        });
    }
);

app.put(
    "/api/players/:id",
    authenticate,
    requireRoles("super_admin", "players_admin"),
    (req, res) => {
        const {
            number,
            name,
            position,
            bio,
            photo
        } = req.body;

        db.prepare(`
            UPDATE players
            SET number=COALESCE(?,number),
                name=COALESCE(?,name),
                position=COALESCE(?,position),
                bio=COALESCE(?,bio),
                photo=COALESCE(?,photo)
            WHERE id=?
        `).run(
            number,
            name,
            position,
            bio,
            photo,
            req.params.id
        );

        res.json({
            message: "Player updated"
        });
    }
);

app.delete(
    "/api/players/:id",
    authenticate,
    requireRoles("super_admin", "players_admin"),
    (req, res) => {
        db.prepare(
            "DELETE FROM players WHERE id=?"
        ).run(req.params.id);

        res.json({
            message: "Player deleted"
        });
    }
);

/* =========================
   VOTING
========================= */

app.post("/api/players/:id/vote", (req, res) => {
    const score = Number(req.body.score);

    if (!Number.isInteger(score) || score < 1 || score > 10) {
        return res.status(400).json({
            error: "Score must be an integer from 1 to 10"
        });
    }

    const player = db.prepare(
        "SELECT * FROM players WHERE id=?"
    ).get(req.params.id);

    if (!player) {
        return res.status(404).json({
            error: "Player not found"
        });
    }

    db.prepare(`
        INSERT INTO votes(player_id,score)
        VALUES(?,?)
    `).run(req.params.id, score);

    const stats = db.prepare(`
        SELECT
            COUNT(*) AS count,
            AVG(score) AS average
        FROM votes
        WHERE player_id=?
    `).get(req.params.id);

    db.prepare(`
        UPDATE players
        SET rating=?, vote_count=?
        WHERE id=?
    `).run(
        Number(stats.average.toFixed(1)),
        stats.count,
        req.params.id
    );

    res.json({
        playerId: Number(req.params.id),
        score,
        rating: Number(stats.average.toFixed(1)),
        voteCount: stats.count
    });
});

/* =========================
   REVIEWS
========================= */

app.post("/api/players/:id/reviews", (req, res) => {
    const { author, body } = req.body;

    if (!author || !body) {
        return res.status(400).json({
            error: "Author and review are required"
        });
    }

    const result = db.prepare(`
        INSERT INTO reviews(player_id,author,body)
        VALUES(?,?,?)
    `).run(req.params.id, author, body);

    res.status(201).json({
        id: result.lastInsertRowid,
        message: "Review submitted"
    });
});

app.get("/api/players/:id/reviews", (req, res) => {
    res.json(
        db.prepare(`
            SELECT *
            FROM reviews
            WHERE player_id=? AND approved=1
            ORDER BY id DESC
        `).all(req.params.id)
    );
});

/* =========================
   NEWS
========================= */

app.get("/api/news", (req, res) => {
    res.json(
        db.prepare(`
            SELECT *
            FROM news
            ORDER BY id DESC
        `).all()
    );
});

app.post(
    "/api/news",
    authenticate,
    requireRoles("super_admin", "content_admin"),
    (req, res) => {
        const { title, body, image = "" } = req.body;

        if (!title || !body) {
            return res.status(400).json({
                error: "Title and body are required"
            });
        }

        const result = db.prepare(`
            INSERT INTO news(title,body,image)
            VALUES(?,?,?)
        `).run(title, body, image);

        res.status(201).json({
            id: result.lastInsertRowid,
            message: "News published"
        });
    }
);

/* =========================
   ANNOUNCEMENTS
========================= */

app.get("/api/announcements", (req, res) => {
    res.json(
        db.prepare(`
            SELECT *
            FROM announcements
            ORDER BY id DESC
        `).all()
    );
});

app.post(
    "/api/announcements",
    authenticate,
    requireRoles("super_admin", "content_admin"),
    (req, res) => {
        const { title, body } = req.body;

        if (!title || !body) {
            return res.status(400).json({
                error: "Title and body are required"
            });
        }

        const result = db.prepare(`
            INSERT INTO announcements(title,body)
            VALUES(?,?)
        `).run(title, body);

        res.status(201).json({
            id: result.lastInsertRowid
        });
    }
);

/* =========================
   FIXTURES / RESULTS
========================= */

app.get("/api/fixtures", (req, res) => {
    res.json(
        db.prepare(`
            SELECT *
            FROM fixtures
            ORDER BY date,time
        `).all()
    );
});

app.post(
    "/api/fixtures",
    authenticate,
    requireRoles("super_admin", "match_admin"),
    (req, res) => {
        const {
            home_team,
            away_team,
            date,
            time,
            venue = "",
            image = ""
        } = req.body;

        if (!home_team || !away_team || !date || !time) {
            return res.status(400).json({
                error: "Teams, date and time are required"
            });
        }

        const result = db.prepare(`
            INSERT INTO fixtures
            (home_team,away_team,date,time,venue,image)
            VALUES(?,?,?,?,?,?)
        `).run(
            home_team,
            away_team,
            date,
            time,
            venue,
            image
        );

        res.status(201).json({
            id: result.lastInsertRowid
        });
    }
);

app.put(
    "/api/fixtures/:id/result",
    authenticate,
    requireRoles("super_admin", "match_admin"),
    (req, res) => {
        const {
            home_score,
            away_score
        } = req.body;

        db.prepare(`
            UPDATE fixtures
            SET home_score=?,
                away_score=?,
                status='completed'
            WHERE id=?
        `).run(
            home_score,
            away_score,
            req.params.id
        );

        res.json({
            message: "Result updated"
        });
    }
);

/* =========================
   GALLERY
========================= */

app.get("/api/gallery", (req, res) => {
    res.json(
        db.prepare(`
            SELECT *
            FROM gallery
            ORDER BY id DESC
        `).all()
    );
});

app.post(
    "/api/gallery",
    authenticate,
    requireRoles("super_admin", "content_admin"),
    (req, res) => {
        const { title, image } = req.body;

        if (!title || !image) {
            return res.status(400).json({
                error: "Title and image are required"
            });
        }

        const result = db.prepare(`
            INSERT INTO gallery(title,image)
            VALUES(?,?)
        `).run(title, image);

        res.status(201).json({
            id: result.lastInsertRowid
        });
    }
);

/* =========================
   NOTIFICATIONS
========================= */

app.get("/api/notifications", (req, res) => {
    res.json(
        db.prepare(`
            SELECT *
            FROM notifications
            ORDER BY id DESC
        `).all()
    );
});

app.post(
    "/api/notifications",
    authenticate,
    requireRoles("super_admin", "content_admin"),
    (req, res) => {
        const { title, body } = req.body;

        const result = db.prepare(`
            INSERT INTO notifications(title,body)
            VALUES(?,?)
        `).run(title, body);

        res.status(201).json({
            id: result.lastInsertRowid
        });
    }
);

/* =========================
   API SUMMARY
========================= */

app.get("/api", (req, res) => {
    res.json({
        name: "Pioneers FC API",
        version: "1.0",
        endpoints: [
            "/api/health",
            "/api/admin/login",
            "/api/admin/me",
            "/api/players",
            "/api/news",
            "/api/announcements",
            "/api/fixtures",
            "/api/gallery",
            "/api/notifications"
        ]
    });
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, "0.0.0.0", () => {
    console.log("");
    console.log("=================================");
    console.log("      PIONEERS FC BACKEND");
    console.log("=================================");
    console.log(`Server: http://127.0.0.1:${PORT}`);
    console.log("Database: pioneers_fc.db");
    console.log("");
    console.log("Four administrators:");
    console.log("  admin1  -> Super Administrator");
    console.log("  admin2  -> Content Administrator");
    console.log("  admin3  -> Players Administrator");
    console.log("  admin4  -> Match Administrator");
    console.log("");
    console.log("Development password:");
    console.log("  PioneersFC@2026");
    console.log("");
    console.log("CHANGE THE DEFAULT PASSWORDS BEFORE PUBLIC DEPLOYMENT.");
    console.log("=================================");
});
