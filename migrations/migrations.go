package migrations

import "embed"

// FS embeds all .sql files in the migrations directory.
//
//go:embed *.sql
var FS embed.FS
