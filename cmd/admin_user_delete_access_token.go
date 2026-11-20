// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"

	"github.com/urfave/cli/v3"
)

func microcmdUserDeleteAccessToken() *cli.Command {
	return &cli.Command{
		Name:  "delete-access-token",
		Usage: "Delete an access token of a specific user, by id or by name",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "username",
				Aliases: []string{"u"},
				Usage:   "Username of the user who owns the token",
			},
			&cli.Int64Flag{
				Name:   "id",
				Usage:  "ID of the access token to delete",
				Config: cli.IntegerConfig{Base: 10},
			},
			&cli.StringFlag{
				Name:    "name",
				Aliases: []string{"t"},
				Usage:   "Name of the access token to delete",
			},
		},
		Before: noDanglingArgs,
		Action: runDeleteAccessToken,
	}
}

func runDeleteAccessToken(ctx context.Context, c *cli.Command) error {
	if !c.IsSet("username") {
		return errors.New("you must provide the username of the user who owns the access token")
	}
	if c.IsSet("id") == c.IsSet("name") {
		return errors.New("you must provide exactly one of --id or --name")
	}
	if c.IsSet("name") && c.String("name") == "" {
		return errors.New("the name of the access token must not be empty")
	}

	ctx, cancel := installSignals(ctx)
	defer cancel()

	if err := initDB(ctx); err != nil {
		return err
	}

	user, err := user_model.GetUserByName(ctx, c.String("username"))
	if err != nil {
		return err
	}

	// Only ever look at the tokens of this user, so that a token of another
	// user can never be matched by its id or name.
	tokens, err := db.Find[auth_model.AccessToken](ctx, auth_model.ListAccessTokensOptions{UserID: user.ID})
	if err != nil {
		return err
	}

	var matches []*auth_model.AccessToken
	for _, t := range tokens {
		if (c.IsSet("id") && t.ID == c.Int64("id")) || (c.IsSet("name") && t.Name == c.String("name")) {
			matches = append(matches, t)
		}
	}

	switch len(matches) {
	case 0:
		if c.IsSet("id") {
			return fmt.Errorf("user %s has no access token with id %d", user.Name, c.Int64("id"))
		}
		return fmt.Errorf("user %s has no access token named %q", user.Name, c.String("name"))
	case 1:
	default:
		ids := make([]int64, 0, len(matches))
		for _, t := range matches {
			ids = append(ids, t.ID)
		}
		return fmt.Errorf("user %s has %d access tokens named %q (ids %v), use --id to choose one", user.Name, len(matches), c.String("name"), ids)
	}

	token := matches[0]
	if err := auth_model.DeleteAccessTokenByID(ctx, token.ID, user.ID); err != nil {
		return err
	}

	fmt.Printf("Access token %q (id %d) of user %s was successfully deleted\n", token.Name, token.ID, user.Name)
	return nil
}
