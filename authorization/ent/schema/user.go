package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.Int("id").
			Positive(),
		field.String("AccountName").Immutable().NotEmpty().MaxLen(256).Unique(),
		field.String("Password").NotEmpty().MaxLen(256).Sensitive(),
		field.String("Sub").NotEmpty().MaxLen(256),
		field.String("NameJa").NotEmpty().MaxLen(256),
		field.String("GivenName").NotEmpty().MaxLen(256),
		field.String("FamilyName").NotEmpty().MaxLen(256),
		field.String("Locale").NotEmpty().MaxLen(2),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return nil
}
