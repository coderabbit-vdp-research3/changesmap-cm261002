<?php
// CHANGESMAP_FAKE_SECRET_SEARCH_261002 — OBVIOUSLY-FAKE test marker (authorized VDP lab fixture).
// Deliberately vulnerable: SQL injection via string concatenation (test fixture only).
$q = "SELECT * FROM products WHERE name = '" . $_GET['q'] . "'";
$result = mysqli_query($conn, $q);
