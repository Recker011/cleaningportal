// Availability Tracking System - ExpressJS Scaffold
// Runs with: npm run dev  -> http://localhost:${process.env.PORT || 3000}
// Features:
// - Login with pre-seeded users (manager1, employee1) - password: password123
// - Employee: set weekly availability (Mon-Sun), Morning/Afternoon + Notes
// - Manager: view availability by filters and edit any user's availability
// - MySQL (mysql2) connection using .env config with optional SSL CA
// - Minimal HTML templates and basic CSS hook (public/styles.css)

"use strict";

require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const helmet = require("helmet");
const compression = require("compression");
const cookieSession = require("cookie-session");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise");

// ---------- Config ----------
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET =
  process.env.SESSION_SECRET || "change_this_to_a_long_random_secret";

const DB_HOST = process.env.DB_HOST;
const DB_PORT = Number(process.env.DB_PORT || 3306);
const DB_NAME = process.env.DB_NAME;
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const DB_SSL_CA_PATH = process.env.DB_SSL_CA_PATH;

const DB_CONN_TIMEOUT = Number(process.env.DB_CONN_TIMEOUT || 10000);
const DB_READ_TIMEOUT = Number(process.env.DB_READ_TIMEOUT || 10000);
const DB_WRITE_TIMEOUT = Number(process.env.DB_WRITE_TIMEOUT || 10000);

const NODE_ENV = process.env.NODE_ENV || "development";

const hasDbConfig =
  !!DB_HOST && !!DB_NAME && !!DB_USER && typeof DB_PASSWORD === "string";

let ssl = undefined;
if (DB_SSL_CA_PATH) {
  try {
    const caPath = path.resolve(DB_SSL_CA_PATH);
    if (fs.existsSync(caPath)) {
      ssl = { ca: fs.readFileSync(caPath, "utf8") };
      console.log(`[DB] Using SSL CA at: ${caPath}`);
    } else {
      console.warn(
        `[DB] SSL CA file not found at ${caPath}, continuing without SSL`
      );
    }
  } catch (e) {
    console.warn(
      "[DB] Unable to read SSL CA file, continuing without SSL",
      e.message
    );
  }
}

let pool = null;
if (hasDbConfig) {
  pool = mysql.createPool({
    host: DB_HOST,
    port: DB_PORT,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: DB_CONN_TIMEOUT,
    ssl,
  });
} else {
  console.warn(
    "[DB] Missing database environment variables. Server will start, but DB-backed features will not work until configured."
  );
}

/* ---------- Helpers ---------- */
const DAYS = [
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
  "Sunday",
];

/** Convert JS Date.getDay (0=Sun..6=Sat) to Monday=0..Sunday=6 */
function getMondayIndexFromDate(date = new Date()) {
  const jsDay = date.getDay(); // 0 (Sun) ... 6 (Sat)
  return (jsDay + 6) % 7; // 0 (Mon) ... 6 (Sun)
}

function escapeHtml(str = "") {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function checkbox(checked) {
  return checked ? "checked" : "";
}

function errorPage(title, message) {
  return `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(title)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="/styles.css" rel="stylesheet">
</head>
<body>
  <div class="container">
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
    <p><a href="/" class="btn">Home</a></p>
  </div>
</body>
</html>
`.trim();
}

function layoutPage(title, contentHtml, user = null) {
  const navLinks = user
    ? user.role === "manager"
      ? `<a href="/">Home</a><a href="/manager-dashboard">Dashboard</a><a href="/manager">Manage</a>`
      : `<a href="/">Home</a><a href="/availability">My Availability</a>`
    : `<a href="/">Home</a><a href="/login">Login</a>`;

  const logoutForm = user
    ? `<form method="post" action="/logout" style="display:inline"><button class="linklike" type="submit">Logout</button></form>`
    : "";

  return `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(title)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="/styles.css" rel="stylesheet">
  <script src="/app.js" defer></script>
</head>
<body>
  <header class="site-header">
    <div class="container">
      <h1>Availability Tracking System</h1>
      <button class="nav-toggle" aria-controls="site-nav" aria-expanded="false" aria-label="Toggle navigation">☰</button>
      <nav id="site-nav">
        ${navLinks}
        ${logoutForm}
      </nav>
    </div>
  </header>
  <main class="container">
    ${contentHtml}
  </main>
  <footer class="site-footer">
  </footer>
</body>
</html>
`.trim();
}

// ---------- DB Migrations & Seed ----------
async function migrateAndSeed() {
  if (!pool) {
    console.warn(
      "[DB] Skipping migrations and seed due to missing DB configuration."
    );
    return;
  }
  try {
    // Users
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('employee','manager') NOT NULL DEFAULT 'employee',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Availability
    await pool.query(`
      CREATE TABLE IF NOT EXISTS availability (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        day_of_week TINYINT NOT NULL,
        morning TINYINT(1) NOT NULL DEFAULT 0,
        afternoon TINYINT(1) NOT NULL DEFAULT 0,
        notes VARCHAR(255) NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_user_day (user_id, day_of_week),
        CONSTRAINT fk_av_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Seed if empty
    const [countRows] = await pool.query("SELECT COUNT(*) AS cnt FROM users");
    const cnt = countRows?.[0]?.cnt || 0;
    if (cnt === 0) {
      console.log("[DB] Seeding default users...");
      const defaultPassword = "password123";
      const hash = await bcrypt.hash(defaultPassword, 10);
      const hash2 = await bcrypt.hash(defaultPassword, 10);

      await pool.query(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?), (?, ?, ?)",
        ["manager1", hash, "manager", "employee1", hash2, "employee"]
      );
      console.log(
        "[DB] Seeded users: manager1 (manager), employee1 (employee) with password: password123"
      );
    }
  } catch (err) {
    console.error("[DB] Migration/Seed error:", err.message);
    console.error(
      "[DB] Server will continue to run, but DB features may not work."
    );
  }
}

// ---------- App ----------
const app = express();

app.disable("x-powered-by");
app.use(helmet());
app.use(compression());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  cookieSession({
    name: "session",
    keys: [SESSION_SECRET],
    httpOnly: true,
    sameSite: "lax",
    secure: NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  })
);

app.use(express.static(path.join(__dirname, "public")));

// Attach current user to req/res locals
app.use((req, res, next) => {
  res.locals.user = req.session?.user || null;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session?.user) {
    return res.redirect("/login");
  }
  next();
}

function requireManager(req, res, next) {
  if (!req.session?.user) {
    return res.redirect("/login");
  }
  if (req.session.user.role !== "manager") {
    return res
      .status(403)
      .send(errorPage("Forbidden", "Manager access required."));
  }
  next();
}

// ---------- Routes ----------
app.get("/", (req, res) => {
  if (req.session?.user) {
    return res.redirect(
      req.session.user.role === "manager"
        ? "/manager-dashboard"
        : "/availability"
    );
  }
  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  if (req.session?.user) {
    return res.redirect(
      req.session.user.role === "manager"
        ? "/manager-dashboard"
        : "/availability"
    );
  }
  const html = `
    <div class="auth-card">
      <h2>Login</h2>
      <form method="post" action="/login" class="form">
        <label>
          Username
          <input type="text" name="username" required placeholder="manager1 or employee1">
        </label>
        <label>
          Password
          <input type="password" name="password" required placeholder="password123">
        </label>
        <button type="submit" class="btn primary">Login</button>
      </form>
    </div>
  `;
  res.send(layoutPage("Login", html, res.locals.user));
});

app.post("/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!username || !password) {
    return res
      .status(400)
      .send(errorPage("Bad Request", "Username and password are required."));
  }

  if (!pool) {
    return res
      .status(500)
      .send(
        errorPage(
          "DB Not Configured",
          "Database is not configured. Check .env."
        )
      );
  }

  try {
    const [rows] = await pool.execute(
      "SELECT id, username, password_hash, role FROM users WHERE username = ? LIMIT 1",
      [username]
    );
    const user = rows?.[0];
    if (!user) {
      return res
        .status(401)
        .send(errorPage("Unauthorized", "Invalid credentials."));
    }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res
        .status(401)
        .send(errorPage("Unauthorized", "Invalid credentials."));
    }
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
    };
    return res.redirect(
      user.role === "manager" ? "/manager-dashboard" : "/availability"
    );
  } catch (err) {
    console.error("[LOGIN] Error:", err.message);
    return res
      .status(500)
      .send(errorPage("Server Error", "Unable to login right now."));
  }
});

app.post("/logout", (req, res) => {
  req.session = null;
  res.redirect("/login");
});

app.get("/availability", requireAuth, async (req, res) => {
  if (!pool) {
    return res
      .status(500)
      .send(
        errorPage(
          "DB Not Configured",
          "Database is not configured. Check .env."
        )
      );
  }
  if (req.session.user.role === "manager") {
    return res.redirect("/manager-dashboard");
  }
  const userId = req.session.user.id;

  try {
    const [rows] = await pool.execute(
      "SELECT day_of_week, morning, afternoon, notes FROM availability WHERE user_id = ?",
      [userId]
    );
    const map = new Map();
    for (const r of rows || []) {
      map.set(Number(r.day_of_week), {
        morning: Number(r.morning) === 1,
        afternoon: Number(r.afternoon) === 1,
        notes: r.notes || "",
      });
    }

    let formRows = "";
    for (let i = 0; i < 7; i++) {
      const data = map.get(i) || {
        morning: false,
        afternoon: false,
        notes: "",
      };
      formRows += `
        <tr>
          <td>${DAYS[i]}</td>
          <td class="center">
            <input type="checkbox" name="d${i}_morning" ${checkbox(
        data.morning
      )}>
          </td>
          <td class="center">
            <input type="checkbox" name="d${i}_afternoon" ${checkbox(
        data.afternoon
      )}>
          </td>
          <td>
            <input type="text" name="d${i}_notes" value="${escapeHtml(
        data.notes
      )}" placeholder="Notes (e.g., only until 5pm)">
          </td>
        </tr>
      `;
    }

    const html = `
      <h2>My Weekly Availability</h2>
      <p class="muted small">Tip: Tick morning/afternoon for each day. Add any constraints in the notes field.</p>
      <form method="post" action="/availability">
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>Day</th>
                <th>Morning</th>
                <th>Afternoon</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              ${formRows}
            </tbody>
          </table>
        </div>
        <button class="btn primary block" type="submit">Save Availability</button>
      </form>
    `;
    res.send(layoutPage("My Availability", html, req.session.user));
  } catch (err) {
    console.error("[AVAILABILITY GET] Error:", err.message);
    return res
      .status(500)
      .send(errorPage("Server Error", "Unable to load availability."));
  }
});

app.post("/availability", requireAuth, async (req, res) => {
  if (!pool) {
    return res
      .status(500)
      .send(
        errorPage(
          "DB Not Configured",
          "Database is not configured. Check .env."
        )
      );
  }
  if (req.session.user.role === "manager") {
    return res.redirect("/manager-dashboard");
  }
  const userId = req.session.user.id;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (let i = 0; i < 7; i++) {
      const morning = req.body[`d${i}_morning`] ? 1 : 0;
      const afternoon = req.body[`d${i}_afternoon`] ? 1 : 0;
      const notes = String(req.body[`d${i}_notes`] || "").slice(0, 255);

      await conn.execute(
        `
        INSERT INTO availability (user_id, day_of_week, morning, afternoon, notes)
        VALUES (?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          morning = VALUES(morning),
          afternoon = VALUES(afternoon),
          notes = VALUES(notes)
        `,
        [userId, i, morning, afternoon, notes]
      );
    }
    await conn.commit();
    res.redirect("/availability");
  } catch (err) {
    await conn.rollback();
    console.error("[AVAILABILITY POST] Error:", err.message);
    res
      .status(500)
      .send(errorPage("Server Error", "Unable to save availability."));
  } finally {
    conn.release();
  }
});

app.get("/manager", requireManager, async (req, res) => {
  if (!pool) {
    return res
      .status(500)
      .send(
        errorPage(
          "DB Not Configured",
          "Database is not configured. Check .env."
        )
      );
  }

  // Filters
  const dayParam = req.query.day;
  const shift = req.query.shift || "any"; // any | morning | afternoon
  const dayIndex =
    dayParam !== undefined && dayParam !== "" ? Number(dayParam) : 0;
  const daySafe =
    isFinite(dayIndex) && dayIndex >= 0 && dayIndex <= 6 ? dayIndex : 0;

  try {
    // We want all employees and their availability for a given day (left join to include missing rows)
    const conditions = ["u.role = 'employee'"];
    const params = [];

    let join =
      "LEFT JOIN availability a ON a.user_id = u.id AND a.day_of_week = ?";
    params.push(daySafe);

    if (shift === "morning") {
      conditions.push("(a.morning = 1)");
    } else if (shift === "afternoon") {
      conditions.push("(a.afternoon = 1)");
    }

    const whereSql = conditions.length
      ? `WHERE ${conditions.join(" AND ")}`
      : "";
    const sql = `
      SELECT u.id as user_id, u.username, a.day_of_week, a.morning, a.afternoon, a.notes
      FROM users u
      ${join}
      ${whereSql}
      ORDER BY u.username ASC
    `;
    const [rows] = await pool.execute(sql, params);

    const optionsDay = DAYS.map((d, i) => {
      return `<option value="${i}" ${
        i === daySafe ? "selected" : ""
      }>${d}</option>`;
    }).join("");

    const optionsShift = ["any", "morning", "afternoon"]
      .map(
        (s) =>
          `<option value="${s}" ${s === shift ? "selected" : ""}>${s}</option>`
      )
      .join("");

    const morningCount = (rows || []).reduce(
      (acc, r) => acc + (Number(r?.morning || 0) === 1 ? 1 : 0),
      0
    );
    const afternoonCount = (rows || []).reduce(
      (acc, r) => acc + (Number(r?.afternoon || 0) === 1 ? 1 : 0),
      0
    );

    let tableRows = "";
    for (const r of rows || []) {
      const morning = Number(r?.morning || 0) === 1;
      const afternoon = Number(r?.afternoon || 0) === 1;
      const notes = r?.notes || "";
      tableRows += `
        <tr>
          <td>${escapeHtml(r.username)}</td>
          <td>${DAYS[daySafe]}</td>
          <td class="center">${morning ? '<span class="badge morning">Yes</span>' : '<span class="badge unavailable">No</span>'}</td>
          <td class="center">${afternoon ? '<span class="badge afternoon">Yes</span>' : '<span class="badge unavailable">No</span>'}</td>
          <td>${escapeHtml(notes)}</td>
          <td><a class="btn small primary" href="/manager/user/${r.user_id}">Edit</a></td>
        </tr>
      `;
    }

    const html = `
      <h2>Manager View</h2>
      <form method="get" action="/manager" class="filters">
        <label>
          Day
          <select name="day">${optionsDay}</select>
        </label>
        <label>
          Shift
          <select name="shift">${optionsShift}</select>
        </label>
        <button class="btn primary" type="submit">Apply Filters</button>
      </form>

      <div class="card-grid">
        <div class="card kpi">
          <div class="kpi-value">${morningCount}</div>
          <div class="kpi-label">Morning available</div>
        </div>
        <div class="card kpi">
          <div class="kpi-value">${afternoonCount}</div>
          <div class="kpi-label">Afternoon available</div>
        </div>
      </div>

      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>User</th>
              <th>Day</th>
              <th>Morning</th>
              <th>Afternoon</th>
              <th>Notes</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${
              tableRows ||
              `<tr><td colspan="6" class="center muted">No results</td></tr>`
            }
          </tbody>
        </table>
      </div>
    `;
    res.send(layoutPage("Manager", html, req.session.user));
  } catch (err) {
    console.error("[MANAGER GET] Error:", err.message);
    res
      .status(500)
      .send(errorPage("Server Error", "Unable to load manager view."));
  }
});

app.get("/manager/user/:id", requireManager, async (req, res) => {
  if (!pool) {
    return res
      .status(500)
      .send(
        errorPage(
          "DB Not Configured",
          "Database is not configured. Check .env."
        )
      );
  }
  const targetUserId = Number(req.params.id);
  if (!isFinite(targetUserId) || targetUserId <= 0) {
    return res.status(400).send(errorPage("Bad Request", "Invalid user id."));
  }

  try {
    const [[u]] = await pool.execute(
      "SELECT id, username, role FROM users WHERE id = ? LIMIT 1",
      [targetUserId]
    );
    if (!u) {
      return res.status(404).send(errorPage("Not Found", "User not found."));
    }

    const [rows] = await pool.execute(
      "SELECT day_of_week, morning, afternoon, notes FROM availability WHERE user_id = ?",
      [targetUserId]
    );
    const map = new Map();
    for (const r of rows || []) {
      map.set(Number(r.day_of_week), {
        morning: Number(r.morning) === 1,
        afternoon: Number(r.afternoon) === 1,
        notes: r.notes || "",
      });
    }

    let formRows = "";
    for (let i = 0; i < 7; i++) {
      const data = map.get(i) || {
        morning: false,
        afternoon: false,
        notes: "",
      };
      formRows += `
        <tr>
          <td>${DAYS[i]}</td>
          <td class="center">
            <input type="checkbox" name="d${i}_morning" ${checkbox(
        data.morning
      )}>
          </td>
          <td class="center">
            <input type="checkbox" name="d${i}_afternoon" ${checkbox(
        data.afternoon
      )}>
          </td>
          <td>
            <input type="text" name="d${i}_notes" value="${escapeHtml(
        data.notes
      )}" placeholder="Notes">
          </td>
        </tr>
      `;
    }

    const html = `
      <h2>Edit Availability: ${escapeHtml(u.username)}</h2>
      <form method="post" action="/manager/user/${u.id}">
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>Day</th>
                <th>Morning</th>
                <th>Afternoon</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              ${formRows}
            </tbody>
          </table>
        </div>
        <button class="btn primary block" type="submit">Save Changes</button>
        <a class="btn" href="/manager">Back to Manager</a>
      </form>
    `;
    res.send(layoutPage("Edit User Availability", html, req.session.user));
  } catch (err) {
    console.error("[MANAGER USER GET] Error:", err.message);
    res
      .status(500)
      .send(errorPage("Server Error", "Unable to load user availability."));
  }
});

app.post("/manager/user/:id", requireManager, async (req, res) => {
  if (!pool) {
    return res
      .status(500)
      .send(
        errorPage(
          "DB Not Configured",
          "Database is not configured. Check .env."
        )
      );
  }
  const targetUserId = Number(req.params.id);
  if (!isFinite(targetUserId) || targetUserId <= 0) {
    return res.status(400).send(errorPage("Bad Request", "Invalid user id."));
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (let i = 0; i < 7; i++) {
      const morning = req.body[`d${i}_morning`] ? 1 : 0;
      const afternoon = req.body[`d${i}_afternoon`] ? 1 : 0;
      const notes = String(req.body[`d${i}_notes`] || "").slice(0, 255);

      await conn.execute(
        `
        INSERT INTO availability (user_id, day_of_week, morning, afternoon, notes)
        VALUES (?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          morning = VALUES(morning),
          afternoon = VALUES(afternoon),
          notes = VALUES(notes)
        `,
        [targetUserId, i, morning, afternoon, notes]
      );
    }
    await conn.commit();
    res.redirect(`/manager/user/${targetUserId}`);
  } catch (err) {
    await conn.rollback();
    console.error("[MANAGER USER POST] Error:", err.message);
    res
      .status(500)
      .send(errorPage("Server Error", "Unable to update user availability."));
  } finally {
    conn.release();
  }
});

/* Manager Dashboard */
app.get("/manager-dashboard", requireManager, async (req, res) => {
  if (!pool) {
    return res
      .status(500)
      .send(
        errorPage(
          "DB Not Configured",
          "Database is not configured. Check .env."
        )
      );
  }

  const todayIdx = getMondayIndexFromDate(new Date());
  const tomorrowIdx = (todayIdx + 1) % 7;

  try {
    const [rows] = await pool.execute(`
      SELECT u.id as user_id, u.username, a.day_of_week, a.morning, a.afternoon, a.notes
      FROM users u
      LEFT JOIN availability a ON a.user_id = u.id
      WHERE u.role = 'employee'
      ORDER BY u.username ASC
    `);

    const people = new Map();
    for (const r of rows || []) {
      const id = r.user_id;
      if (!people.has(id)) {
        people.set(id, { id, username: r.username, days: new Map() });
      }
      if (r.day_of_week !== null && r.day_of_week !== undefined) {
        people.get(id).days.set(Number(r.day_of_week), {
          morning: Number(r.morning || 0) === 1,
          afternoon: Number(r.afternoon || 0) === 1,
          notes: r.notes || "",
        });
      }
    }
    const employees = Array.from(people.values()).sort((a, b) =>
      a.username.localeCompare(b.username)
    );

    const todayName = DAYS[todayIdx];
    const tomorrowName = DAYS[tomorrowIdx];

    function dayAvail(person, idx) {
      const d = person.days.get(idx) || {
        morning: false,
        afternoon: false,
        notes: "",
      };
      return d;
    }

    const todayMorning = employees.filter((p) => dayAvail(p, todayIdx).morning);
    const todayAfternoon = employees.filter(
      (p) => dayAvail(p, todayIdx).afternoon
    );
    const tomorrowMorning = employees.filter(
      (p) => dayAvail(p, tomorrowIdx).morning
    );
    const tomorrowAfternoon = employees.filter(
      (p) => dayAvail(p, tomorrowIdx).afternoon
    );

    function list(items) {
      if (items.length === 0) return '<div class="muted">None</div>';
      return `<ul class="plain">${items
        .map((p) => `<li>${escapeHtml(p.username)}</li>`)
        .join("")}</ul>`;
    }

    function weeklyTable() {
      const header = DAYS.map((d) => `<th>${d.slice(0, 3)}</th>`).join("");
      const rowsHtml = employees
        .map((p) => {
          const cells = DAYS.map((_, i) => {
            const d = dayAvail(p, i);
            const m = d.morning;
            const a = d.afternoon;
            return `
              <td class="center">
                <span class="dot ${
                  m ? "available" : ""
                }" title="Morning"></span>
                <span class="dot ${
                  a ? "available" : ""
                }" title="Afternoon"></span>
              </td>
            `;
          }).join("");
          return `<tr><td>${escapeHtml(p.username)}</td>${cells}</tr>`;
        })
        .join("");
      return `
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr><th>User</th>${header}</tr>
            </thead>
            <tbody>${
              rowsHtml ||
              `<tr><td colspan="8" class="center muted">No employees</td></tr>`
            }</tbody>
          </table>
        </div>
        <div class="legend muted small" role="note" aria-label="Legend">
          <span class="dot available" aria-hidden="true"></span> Available
          <span class="dot" aria-hidden="true" style="margin-left:12px;"></span> Not available
        </div>
      `;
    }

    function employeeCards() {
      return `
        <div class="card-grid">
          ${employees
            .map((p) => {
              const rows = DAYS.map((d, i) => {
                const da = dayAvail(p, i);
                const b1 = da.morning
                  ? `<span class="badge morning">Morning</span>`
                  : "";
                const b2 = da.afternoon
                  ? `<span class="badge afternoon">Afternoon</span>`
                  : "";
                const none =
                  !da.morning && !da.afternoon
                    ? `<span class="badge unavailable">Unavailable</span>`
                    : "";
                const notes = da.notes
                  ? `<span class="muted">— ${escapeHtml(da.notes)}</span>`
                  : "";
                return `<div class="row"><strong>${d}</strong> <span class="spacer"></span> ${b1}${b2}${none} ${notes}</div>`;
              }).join("");
              return `
                <div class="card">
                  <h3>${escapeHtml(p.username)}</h3>
                  <div class="mini-rows">
                    ${rows}
                  </div>
                  <div class="muted" style="margin-top:8px;font-size:12px;">Badges indicate availability per shift</div>
                </div>
              `;
            })
            .join("")}
        </div>
      `;
    }

    const html = `
      <section class="section">
        <h2>Available Today <span class="muted">(${escapeHtml(
          todayName
        )})</span></h2>
        <div class="card-grid">
          <div class="card">
            <h3>Morning</h3>
            ${list(todayMorning)}
          </div>
          <div class="card">
            <h3>Afternoon</h3>
            ${list(todayAfternoon)}
          </div>
        </div>
      </section>

      <section class="section">
        <h2>Available Tomorrow <span class="muted">(${escapeHtml(
          tomorrowName
        )})</span></h2>
        <div class="card-grid">
          <div class="card">
            <h3>Morning</h3>
            ${list(tomorrowMorning)}
          </div>
          <div class="card">
            <h3>Afternoon</h3>
            ${list(tomorrowAfternoon)}
          </div>
        </div>
      </section>

      <section class="section">
        <h2>Weekly Overview</h2>
        ${weeklyTable()}
      </section>

      <section class="section">
        <h2>Employees</h2>
        ${employeeCards()}
      </section>
    `;
    res.send(layoutPage("Manager Dashboard", html, req.session.user));
  } catch (err) {
    console.error("[MANAGER DASHBOARD] Error:", err.message);
    res
      .status(500)
      .send(errorPage("Server Error", "Unable to load manager dashboard."));
  }
});

// Health check
app.get("/healthz", async (req, res) => {
  if (!pool) return res.status(200).json({ ok: true, db: false });
  try {
    await pool.query("SELECT 1");
    return res.status(200).json({ ok: true, db: true });
  } catch {
    return res.status(200).json({ ok: true, db: false });
  }
});

// 404 handler
app.use((req, res) => {
  res
    .status(404)
    .send(errorPage("Not Found", "The page you requested was not found."));
});

// Error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error("[APP ERROR]", err);
  res
    .status(500)
    .send(errorPage("Server Error", "An unexpected error occurred."));
});

// Start-up
(async () => {
  try {
    await migrateAndSeed();
  } catch (e) {
    // Already logged inside migrateAndSeed
  }
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
})();

// Safety
process.on("unhandledRejection", (reason) => {
  console.error("[unhandledRejection]", reason);
});
