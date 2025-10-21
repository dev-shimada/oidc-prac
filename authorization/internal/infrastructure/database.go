package infrastructure

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/dev-shimada/oidc-prac/authorization/ent"
)

func NewDB() *ent.Client {
	client, err := ent.Open("sqlite3", "./authorization.db?_fk=1")
	if err != nil {
		slog.Error(fmt.Sprintf("failed opening connection to sqlite: %v", err))
	}
	return client
}

func MigrateDB(client *ent.Client) {
	ctx := context.Background()
	if err := client.Schema.Create(ctx); err != nil {
		slog.Error(fmt.Sprintf("failed creating schema resources: %v", err))
	}
}

func CloseDB(client *ent.Client) {
	if err := client.Close(); err != nil {
		slog.Error(fmt.Sprintf("Failed to close database connection: %v", err))
	}
}
