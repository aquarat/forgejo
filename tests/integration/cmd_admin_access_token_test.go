// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Cmd_AdminUserAccessTokens(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

		// Fixtures: user1 owns "Token A" (id 1) and "Token B" (id 2), user2 owns "Token A" (id 3).
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: 1, UID: 1, Name: "Token A"})
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: 2, UID: 1, Name: "Token B"})
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: 3, UID: 2, Name: "Token A"})

		generated, err := runMainApp("admin", "user", "generate-access-token", "--username", user2.Name, "--token-name", "cli-token", "--scopes", "read:repository", "--raw")
		require.NoError(t, err)
		secret := strings.TrimSpace(generated)
		require.Len(t, secret, 40)
		cliToken := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: user2.ID, Name: "cli-token"})

		t.Run("list", func(t *testing.T) {
			output, err := runMainApp("admin", "user", "list-access-tokens", "--username", user2.Name)
			require.NoError(t, err)
			lines := strings.Split(strings.TrimSpace(output), "\n")
			require.Len(t, lines, 3)
			assert.Regexp(t, `^ID\s+Name\s+Scope\s+Repositories\s+Created\s+LastUsed$`, lines[0])
			// newest first
			assert.Regexp(t, `^\d+\s+"cli-token"\s+read:repository\s+all\s+\S+Z\s+never$`, lines[1])
			assert.Regexp(t, `^3\s+"Token A"\s+-\s+all\s+2000-01-01T00:53:00Z\s+never$`, lines[2])

			// never print the token, its hash, salt or last eight characters
			assert.NotContains(t, output, secret)
			assert.NotContains(t, output, cliToken.TokenHash)
			assert.NotContains(t, output, cliToken.TokenSalt)
			assert.NotContains(t, output, cliToken.TokenLastEight)
		})

		t.Run("list shows tokens restricted to specific repositories", func(t *testing.T) {
			restricted := &auth_model.AccessToken{UID: user2.ID, Name: "restricted", Scope: auth_model.AccessTokenScopeAll, ResourceAllRepos: false}
			require.NoError(t, auth_model.NewAccessToken(t.Context(), restricted))
			defer func() {
				require.NoError(t, auth_model.DeleteAccessTokenByID(t.Context(), restricted.ID, user2.ID))
			}()

			output, err := runMainApp("admin", "user", "list-access-tokens", "--username", user2.Name)
			require.NoError(t, err)
			assert.Regexp(t, `(?m)^\d+\s+"restricted"\s+all\s+specific\s+\S+Z\s+never$`, output)
			assert.NotContains(t, output, restricted.Token)
		})

		t.Run("list requires an existing user", func(t *testing.T) {
			_, err := runMainApp("admin", "user", "list-access-tokens")
			require.Error(t, err)
			_, err = runMainApp("admin", "user", "list-access-tokens", "--username", "no-such-user")
			require.Error(t, err)
		})

		t.Run("delete argument checks", func(t *testing.T) {
			for _, args := range [][]string{
				{"--id", "3"},
				{"--username", user2.Name},
				{"--username", user2.Name, "--id", "3", "--name", "Token A"},
				{"--username", user2.Name, "--id", "0"},
				{"--username", user2.Name, "--name", ""},
				{"--username", "no-such-user", "--id", "3"},
			} {
				_, err := runMainApp("admin", append([]string{"user", "delete-access-token"}, args...)...)
				require.Error(t, err, args)
			}
			unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: 3, UID: 2})
		})

		t.Run("delete never touches the tokens of another user", func(t *testing.T) {
			// id 1 belongs to user1
			_, err := runMainApp("admin", "user", "delete-access-token", "--username", user2.Name, "--id", "1")
			require.Error(t, err)
			unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: 1, UID: 1})

			// "Token B" only exists for user1
			_, err = runMainApp("admin", "user", "delete-access-token", "--username", user2.Name, "--name", "Token B")
			require.Error(t, err)
			unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: 2, UID: 1})

			// "Token A" exists for both users: only the one of user2 goes
			output, err := runMainApp("admin", "user", "delete-access-token", "--username", user2.Name, "--name", "Token A")
			require.NoError(t, err)
			assert.Contains(t, output, `Access token "Token A" (id 3) of user user2 was successfully deleted`)
			unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: 3})
			unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: 1, UID: 1, Name: "Token A"})

			// deleting it again fails
			_, err = runMainApp("admin", "user", "delete-access-token", "--username", user2.Name, "--id", "3")
			require.Error(t, err)
		})

		t.Run("delete by id", func(t *testing.T) {
			output, err := runMainApp("admin", "user", "delete-access-token", "-u", user2.Name, "--id", cliTokenID(cliToken))
			require.NoError(t, err)
			assert.Contains(t, output, `Access token "cli-token"`)
			assert.NotContains(t, output, secret)
			unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: cliToken.ID})
		})

		t.Run("delete refuses an ambiguous name", func(t *testing.T) {
			// the CLI and the UI refuse duplicate names, but older databases or the API may have them
			first := &auth_model.AccessToken{UID: user2.ID, Name: "duplicate", Scope: auth_model.AccessTokenScopeAll, ResourceAllRepos: true}
			require.NoError(t, auth_model.NewAccessToken(t.Context(), first))
			second := &auth_model.AccessToken{UID: user2.ID, Name: "duplicate", Scope: auth_model.AccessTokenScopeAll, ResourceAllRepos: true}
			require.NoError(t, auth_model.NewAccessToken(t.Context(), second))

			output, err := runMainApp("admin", "user", "delete-access-token", "--username", user2.Name, "--name", "duplicate")
			require.Error(t, err)
			assert.Empty(t, output)
			unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: first.ID})
			unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: second.ID})

			_, err = runMainApp("admin", "user", "delete-access-token", "--username", user2.Name, "--id", cliTokenID(second))
			require.NoError(t, err)
			unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: first.ID})
			unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: second.ID})

			// no longer ambiguous
			_, err = runMainApp("admin", "user", "delete-access-token", "--username", user2.Name, "--name", "duplicate")
			require.NoError(t, err)
			unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: first.ID})
		})

		// the tokens of user1 were never touched
		unittest.AssertCount(t, &auth_model.AccessToken{UID: 1}, 2)
	})
}

func cliTokenID(t *auth_model.AccessToken) string {
	return strconv.FormatInt(t.ID, 10)
}
