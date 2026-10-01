// CHANGESMAP_FAKE_SECRET_261002 — OBVIOUSLY-FAKE test marker (authorized VDP lab fixture).
// Deliberately vulnerable snippet planted so the reviewer MUST object (changes-requested cell).
function handle(req, res) {
  const out = eval(req.query.x); // CHANGESMAP planted eval sink — test fixture only
  res.end(String(out));
}
module.exports = { handle };
