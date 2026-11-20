// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"

	"github.com/urfave/cli/v3"
)

func microcmdUserListAccessTokens() *cli.Command {
	return &cli.Command{
		Name:  "list-access-tokens",
		Usage: "List the access tokens of a specific user (token values are never shown)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "username",
				Aliases: []string{"u"},
				Usage:   "Username",
			},
		},
		Before: noDanglingArgs,
		Action: runListAccessTokens,
	}
}

func runListAccessTokens(ctx context.Context, c *cli.Command) error {
	if !c.IsSet("username") {
		return errors.New("you must provide a username to list the access tokens of")
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

	tokens, err := db.Find[auth_model.AccessToken](ctx, auth_model.ListAccessTokensOptions{UserID: user.ID})
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 1, ' ', 0)
	fmt.Fprint(w, "ID\tName\tScope\tRepositories\tCreated\tLastUsed\n")
	for _, t := range tokens {
		scope := string(t.Scope)
		if scope == "" {
			scope = "-"
		} else if strings.ContainsFunc(scope, unicode.IsSpace) {
			scope = strconv.Quote(scope)
		}
		repositories := "all"
		if !t.ResourceAllRepos {
			repositories = "specific"
		}
		lastUsed := "never"
		if t.HasUsed {
			lastUsed = formatAccessTokenTime(t.UpdatedUnix.AsTime())
		}
		fmt.Fprintf(w, "%d\t%q\t%s\t%s\t%s\t%s\n", t.ID, t.Name, scope, repositories, formatAccessTokenTime(t.CreatedUnix.AsTime()), lastUsed)
	}

	return w.Flush()
}

func formatAccessTokenTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
