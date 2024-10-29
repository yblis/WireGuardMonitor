const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs').promises;
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();

// Configuration CORS
app.use(cors({
origin: 'http://87.106.78.99:5173',
methods: ['GET', 'POST', 'PUT', 'DELETE'],
credentials: true,
}));

app.use(express.json());
// Configuration SQLite
const dbPath = path.join(__dirname, 'wireguard.db');
const db = new sqlite3.Database(dbPath);

// Initialisation de la base de données
// Initialisation de la base de données
const initDb = () => {
return new Promise((resolve, reject) => {
const migrations = `
CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
public_key TEXT UNIQUE NOT NULL,
username TEXT NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS daily_stats (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER,
date DATE,
hours_connected FLOAT,
transfer_rx BIGINT,
transfer_tx BIGINT,
FOREIGN KEY (user_id) REFERENCES users (id),
UNIQUE(user_id, date)
);

CREATE INDEX IF NOT EXISTS idx_daily_stats_user_date
ON daily_stats(user_id, date);
`;

db.exec(migrations, (err) => {
if (err) {
console.error('Error during migration:', err);
// Si la table existe déjà, essayez d'ajouter la contrainte UNIQUE
if (err.message.includes('table "daily_stats" already exists')) {
const alterTable = `
CREATE TABLE IF NOT EXISTS daily_stats_new (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER,
date DATE,
hours_connected FLOAT,
transfer_rx BIGINT,
transfer_tx BIGINT,
FOREIGN KEY (user_id) REFERENCES users (id),
UNIQUE(user_id, date)
);

INSERT OR IGNORE INTO daily_stats_new
SELECT * FROM daily_stats;

DROP TABLE daily_stats;
ALTER TABLE daily_stats_new RENAME TO daily_stats;

CREATE INDEX IF NOT EXISTS idx_daily_stats_user_date
ON daily_stats(user_id, date);
`;

db.exec(alterTable, (alterErr) => {
if (alterErr) {
console.error('Error during table alteration:', alterErr);
reject(alterErr);
} else {
console.log('Table successfully altered');
resolve();
}
});
} else {
reject(err);
}
} else {
console.log('Database initialized successfully');
resolve();
}
});
});
};



// Fonction pour sauvegarder ou mettre à jour un utilisateur
const saveUser = async (publicKey, username) => {
return new Promise((resolve, reject) => {
const sql = `
INSERT INTO users (public_key, username)
VALUES (?, ?)
ON CONFLICT(public_key) DO UPDATE SET username = ?
RETURNING id
`;
db.get(sql, [publicKey, username, username], (err, row) => {
if (err) reject(err);
else resolve(row ? row.id : null);
});
});
};

// Fonction pour sauvegarder les statistiques quotidiennes
// Fonction pour sauvegarder les statistiques quotidiennes
const saveDailyStats = async (userId, date, hoursConnected, transferRx, transferTx) => {
return new Promise((resolve, reject) => {
const sql = `
INSERT OR REPLACE INTO daily_stats (user_id, date, hours_connected, transfer_rx, transfer_tx)
VALUES (?, ?,
CASE
WHEN EXISTS (SELECT 1 FROM daily_stats WHERE user_id = ? AND date = ?)
THEN MAX((SELECT hours_connected FROM daily_stats WHERE user_id = ? AND date = ?), ?)
ELSE ?
END,
?, ?
)
`;
db.run(sql, [
userId, date,
userId, date,
userId, date, hoursConnected,
hoursConnected,
transferRx, transferTx
], (err) => {
if (err) {
console.error('Error saving daily stats:', err);
reject(err);
} else {
resolve();
}
});
});
};


// Fonction pour récupérer l'historique des statistiques
const getDailyStats = async (userId, days = 30) => {
return new Promise((resolve, reject) => {
const sql = `
SELECT
date,
hours_connected as hours,
transfer_rx,
transfer_tx
FROM daily_stats
WHERE user_id = ?
AND date >= date('now', '-' || ? || ' days')
ORDER BY date ASC
`;
db.all(sql, [userId, days], (err, rows) => {
if (err) reject(err);
else resolve(rows || []);
});
});
};

// Chemin vers le fichier de configuration WireGuard
const WG_CONFIG = '/etc/wireguard/wg0.conf';

// Fonction pour lire les noms d'utilisateurs depuis les commentaires
async function getUserNames() {
try {
const config = await fs.readFile(WG_CONFIG, 'utf8');
const users = {};
let currentPeer = null;

config.split('\n').forEach(line => {
const peerMatch = line.match(/\[Peer\]/);
const pubKeyMatch = line.match(/PublicKey\s*=\s*(.+)/);
const commentMatch = line.match(/#\s*User:\s*(.+)/);

if (peerMatch) {
currentPeer = null;
} else if (pubKeyMatch && currentPeer === null) {
currentPeer = pubKeyMatch[1];
} else if (commentMatch && currentPeer) {
users[currentPeer] = commentMatch[1];
}
});

return users;
} catch (error) {
console.error('Error reading config file:', error);
return {};
}
}

async function parseWgShowDump() {
return new Promise(async (resolve, reject) => {
try {
const userNames = await getUserNames();

exec('sudo wg show all dump', async (error, stdout, stderr) => {
if (error) {
reject(error);
return;
}

const lines = stdout.trim().split('\n');
const users = {};
const now = Date.now();
const today = new Date().toISOString().split('T')[0];

for (const line of lines) {
const [interface, publicKey, presharedKey, endpoint, allowedIps, latestHandshake, transferRx, transferTx] = line.split('\t');

if (publicKey) {
const username = userNames[publicKey] || 'Unknown';
const handshakeTime = parseInt(latestHandshake) * 1000;
const connectedHours = handshakeTime ? Math.round((now - handshakeTime) / (1000 * 60 * 60) * 100) / 100 : 0;
const rxBytes = parseInt(transferRx || 0);
const txBytes = parseInt(transferTx || 0);

try {
// Sauvegarder l'utilisateur et obtenir son ID
const userId = await saveUser(publicKey, username);

// Sauvegarder les statistiques du jour
await saveDailyStats(userId, today, connectedHours, rxBytes, txBytes);

// Récupérer l'historique
const dailyStats = await getDailyStats(userId);

users[publicKey] = {
username,
interface,
publicKey,
allowedIps,
connectedHours,
transferRx: rxBytes,
transferTx: txBytes,
dailyStats
};
} catch (err) {
console.error(`Error processing user ${username}:`, err);
}
}
}

resolve(users);
});
} catch (error) {
reject(error);
}
});
}

// Initialiser la base de données au démarrage
initDb()
.then(() => console.log('Database initialized successfully'))
.catch(err => console.error('Database initialization failed:', err));

// Route pour obtenir les statistiques
app.get('/api/stats', async (req, res) => {
try {
const stats = await parseWgShowDump();
res.json(stats);
} catch (error) {
console.error('Error in /api/stats:', error);
res.status(500).json({
error: 'Failed to get WireGuard stats',
details: error.message
});
}
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
console.log(`Server running on port ${PORT}`);
});
