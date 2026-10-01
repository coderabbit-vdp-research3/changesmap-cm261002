// CHANGESMAP_FAKE_SECRET_CHAIN_261002 — OBVIOUSLY-FAKE test marker (authorized VDP lab fixture).
// Escalation fixture (run 2): command injection + eval + SQLi string concatenated.
const { exec } = require("child_process");
function run(req, res) {
  exec("ls " + req.query.dir, (e, out) => res.end(out)); // command injection sink
  const q = "SELECT * FROM users WHERE id = " + req.query.id; // SQL injection sink
  res.end(eval(req.query.x)); // eval sink
}
module.exports = { run };
