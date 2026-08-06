// Deliberately vulnerable fixture. Not a real application. Do not deploy.
const sqlite3 = require("sqlite3");

const conn = new sqlite3.Database("./app.db");

// SQL injection: the id is interpolated straight into the statement.
function getUser(id, cb) {
	conn.get(`SELECT id, email, role FROM users WHERE id = '${id}'`, cb);
}

function reset() {
	conn.run("DELETE FROM sessions");
}

module.exports = { getUser, reset };
