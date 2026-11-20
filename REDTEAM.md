# Hacking week: Monday 7 to Friday 11 December 2026

The brief for the Red Teamers. During this week the deployment on Azure of this repository is a target: this is the
owner saying so, as `SECURITY.md` asks.

## The target

- The app on the address I announce at the start of the week. Nothing else.
- The code is public: this repository. Reading it, its history, the workflows and the image on ghcr.io is allowed and
  expected.

## The task: get the flag

There is one flag, in the form `FLAG{...}`, in a note of one account. Notes are encrypted per owner and only shown to
that owner. One account has fewer restrictions than the others. Get the flag, and hand it in with how you got it.

## More challenges

Each of these is something the app is built to prevent. Managing one is a finding, whether or not it brings you the
flag.

1. Read or change a note that is not yours.
2. Run your own script in someone else's browser.
3. Make the app do something for a logged-in user without them knowing, from another site.
4. Log in as someone else: without their password, or with only the password.
5. Use the same code from the authenticator twice, or keep using a session after logging out or a password change.
6. Make the app show an error that tells you something it should not: a stack trace, a query, a path.
7. Find a secret: in this repository, in its history, or in the image on ghcr.io.
8. Get around the attempt limits.

## Hints

Two hints, each from a set day on. Ask me for one; using a hint is fine, just say so when you hand in the flag.

- **Hint 1, from Tuesday 8 December:** a file name.
- **Hint 2, from Thursday 10 December:** a string.

What a hint means, and where it fits, is up to you.

## Rules

- Only the app on the announced address. Not Azure itself (the subscription, the vaults, the database server), not
  GitHub, and not the apps of others.
- No denial of service: no floods and no load tests. A scanner at a moderate rate is fine.
- The attempt limits are higher this week: 100 failed logins per address per 15 minutes, and 60 new accounts per
  address per hour. The whole class shares the address of the school, so a fast tool from school slows everyone down.
- If you get into the account with the flag: take the flag, and leave the rest. Do not change its password or its
  two-step verification, do not change or delete its notes, and do not delete the account, so the others can still try.
- No real personal data in notes or usernames. Accounts you make are gone after the week.
- No social engineering of me or of classmates, other than asking for the hints.

## Handing in

- **The flag:** send it to me, with the steps that got you there.
- **A finding** (one of the challenges, or anything else): report it privately through **Security → Report a
  vulnerability** on this repository, as `SECURITY.md` describes: what you did, what happened and what you expected.

The Blue Team is watching: failed logins, lockouts, errors and reads of the secrets send them a mail. Being noticed is
part of it.
