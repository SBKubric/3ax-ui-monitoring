// Package deps pins the module's direct dependencies while the tree is being
// built out, so that `go mod tidy` keeps them in go.mod before every package
// that uses them exists. It is removed once the build is complete.
package deps

import (
	_ "github.com/caddyserver/certmagic"
	_ "github.com/google/uuid"
	_ "golang.org/x/crypto/bcrypt"
	_ "gorm.io/driver/sqlite"
	_ "gorm.io/gorm"
)
