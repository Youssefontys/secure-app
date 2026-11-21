# Deploying on Azure: the state storage if it is not there yet (setup_azure.py), the image GitHub built,
# Terraform, and if you want, deploying from GitHub after your approval (MIT-44). Start through deployment.py.

import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import deployment
from deployment import REPO, ask, az, check_tools, gh, git, github_repo, hackmode, stop, terraform, yes

# If a tenant requires MFA, az login skips it (AADSTS50076) and there is no subscription; --tenant does ask for it.
AZ_LOGIN_HELP = """First sign in to Azure: you are not signed in yet, or no subscription was found.
   az login
   Does az login say "Authentication failed against tenant <ID>" with AADSTS50076? Then that tenant wants a
   second step (MFA). Sign in to that tenant, and approve it in your authenticator app:
   az login --tenant <ID>
   Then again: python scripts/deployment.py azure"""
# An email address, as an allowlist (MIT-22); the same rule as the validation of alert_email in terraform/variables.tf.
EMAIL = r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}"
EMAILS = rf"-|{EMAIL}(,{EMAIL})*"  # none (-), or addresses separated by commas
# How long the alerts a deploy fires itself stay without a mail, from each opening (alerts.tf, the rule "deploy"): the
# same 30 minutes as every alert's pause after a mail, so one number everywhere. They look back 15 minutes, so the last
# firing comes up to 15 minutes after the last Key Vault read: measured on 20-11-2026, reads until 00:39:29, the apply
# done at 00:40:20, firings at 00:44, 00:49 and 00:54:31. 15 would have fit by 49 seconds; 20 is no pause Azure allows.
MUTE_MINUTES = 30
# The schema job (app.tf): the names follow from local.name in main.tf, which never changes.
SCHEMA_JOB = ["--resource-group", "rg-notes", "--name", "caj-notes-schema"]


# Is the image there, and may everyone pull it? It must: Container Apps does not sign in to ghcr.io.
# Returns its digest (sha256:...), or None: the app is deployed by digest, so what runs cannot change under a tag.
def image_digest(repo, tag):
    accept = ("application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, "
              "application/vnd.docker.distribution.manifest.v2+json")
    try:
        with urllib.request.urlopen(f"https://ghcr.io/token?scope=repository:{repo}:pull", timeout=15) as response:
            token = json.load(response)["token"]
        request = urllib.request.Request(f"https://ghcr.io/v2/{repo}/manifests/{tag}", method="HEAD",
                                         headers={"Authorization": f"Bearer {token}", "Accept": accept})
        with urllib.request.urlopen(request, timeout=15) as response:
            digest = response.headers.get("Docker-Content-Digest", "")
            return digest if response.status == 200 and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) else None
    except (urllib.error.URLError, KeyError, ValueError):
        return None


# All outputs of Terraform at once, by name; {} without a state. Every call fetches the whole state from Azure, about
# half a minute, so once before the apply and once after it, not once per value.
def outputs():
    result = subprocess.run([shutil.which("terraform"), "-chdir=terraform", "output", "-json"],
                            cwd=REPO, capture_output=True, text=True)
    if result.returncode != 0:
        return {}
    return {name: out["value"] for name, out in json.loads(result.stdout or "{}").items() if out.get("value") is not None}


# The app follows wherever the state storage actually lives, read live from Azure: one real source, instead of a
# second region (variables.tf's own default) that only matches by coincidence. "" if backend.conf or the group is gone.
def state_region():
    conf = (REPO / "backend.conf").read_text(encoding="utf-8")
    match = re.search(r'resource_group_name\s*=\s*"([^"]+)"', conf)
    if not match:
        return ""
    return az("group", "show", "--name", match.group(1), "--query", "location", "-o", "tsv", ignore_error=True) or ""


# Opens the window of the rule that holds back the mails a deploy causes itself, from now on for MUTE_MINUTES. Before
# the first apply the rule does not exist yet (no rule_id), and Terraform gives it a first window itself. A failure
# only costs a mail about your own deploy, so it warns instead of stopping. Only the opening after Terraform says so:
# that is the window that counts.
def mute_own_alerts(rule_id, announce=True):
    if not rule_id:
        return
    url = f"https://management.azure.com{rule_id}?api-version=2021-08-08"
    got = az("rest", "--method", "get", "--url", url, ignore_error=True)
    if got is not None:
        rule = json.loads(got)
        start = datetime.now(timezone.utc)
        until = start + timedelta(minutes=MUTE_MINUTES)
        rule["properties"]["schedule"] = {"effectiveFrom": f"{start:%Y-%m-%dT%H:%M:%S}",
                                          "effectiveUntil": f"{until:%Y-%m-%dT%H:%M:%S}", "timeZone": "UTC"}
        # As a file: az is a .cmd on Windows, and cmd.exe mangles the quotes of JSON on the command line.
        with tempfile.TemporaryDirectory() as folder:
            body = Path(folder) / "rule.json"
            body.write_text(json.dumps({key: rule[key] for key in ("location", "tags", "properties") if key in rule}),
                            encoding="utf-8")
            put = az("rest", "--method", "put", "--url", url, "--body", f"@{body}", ignore_error=True)
        if put is not None:
            if announce:
                print(f"\n🔕 Mails about this deploy itself (Key Vault reads, a new revision, roles) held back until "
                      f"{until.astimezone():%H:%M}")
            return
    print("⚠️  Could not hold back the mails about this deploy itself; a mail from the Key Vault alert may follow.")


# az containerapp job ... for the schema job, as text; "" if az cannot tell.
def schema_job(*args):
    return az("containerapp", "job", *args, *SCHEMA_JOB, "-o", "tsv", ignore_error=True) or ""


# Waits until one run of the schema job is no longer running, and returns how it ended.
def schema_run_status(run):
    status, until = "", time.monotonic() + 420  # the job's own deadline is 300 s (app.tf), plus starting up
    while run and time.monotonic() < until:
        status = schema_job("execution", "show", "--job-execution-name", run, "--query", "properties.status")
        if status not in ("Running", "Processing"):
            break
        time.sleep(10)
    return status


# Terraform starts the schema job but does not wait for it, and without it the app cannot log in to the database: every
# login and registration is a 500. On 20-11-2026 its container never started (the log shows the image pulled, then
# nothing until the deadline), and started again by hand it was done in 35 s. So wait for its last run here, and if
# that did not succeed, start it once more. A deploy that did not start it finds the earlier run, and is done at once.
def check_schema_job():
    print("\n🗄️  The database: the schema job, which sets the password the app logs in with")
    run = schema_job("execution", "list", "--query", "sort_by([], &properties.startTime)[-1].name")
    status = schema_run_status(run)
    if run and status != "Succeeded":
        print(f"   ⚠️  Its last run ended as {status or 'unknown'}; starting it once more")
        run = schema_job("start", "--query", "name")
        status = schema_run_status(run)
    if status == "Succeeded":
        print("   ✅ Ready")
    else:
        print("   ⚠️  Not seen to finish. If logging in or registering gives an error, start it by hand; if that fails\n"
              "      too, look at the job caj-notes-schema in the portal (Execution history):\n"
              f"      az containerapp job start {' '.join(SCHEMA_JOB)}")


# What is wrong in the answers of the app on Azure; empty is fine. The same checks as Deploy on GitHub (CD-azure.yml;
# change both together): HSTS, the CSP and the other headers, the session cookie with the flags of __Host- (MIT-21,
# MIT-23, MIT-40), and HTTP that goes to HTTPS with a 301.
def site_problems(headers, plain):
    want = {"Strict-Transport-Security": "max-age=", "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
    problems = [f"no {name}: {value}" for name, value in want.items() if value.lower() not in (headers.get(name) or "").lower()]
    cookie = next((c for c in headers.get_all("Set-Cookie") or [] if c.startswith("__Host-session=")), None)
    flags = [part.strip().lower() for part in (cookie or "").split(";")[1:]]
    if cookie is None:
        problems.append("no session cookie __Host-session")
    else:
        problems += [f"the cookie __Host-session without {flag}" for flag in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/")
                     if flag.lower() not in flags]
    if any(flag.startswith("domain=") for flag in flags):
        problems.append("the cookie __Host-session has a Domain")
    if plain is None or plain.status != 301 or not (plain.headers.get("Location") or "").startswith("https://"):
        problems.append(f"HTTP does not go to HTTPS with a 301 (got {plain.status if plain else 'no answer'})")
    return problems


# The app on Azure, asked as a browser would, without following redirects. Terraform sets what decides these answers
# (HTTPS_ONLY and allow_insecure_connections in app.tf), and this script is what runs Terraform, so they are checked
# here, after every deployment; Deploy on GitHub only replaces the image. A new revision can take a minute to answer.
def live_problems(url):
    class Stay(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            return None

    def fetch(address):
        try:
            return urllib.request.build_opener(Stay).open(address, timeout=30)
        except urllib.error.HTTPError as error:
            return error
        except OSError:
            return None

    for _ in range(10):
        page = fetch(f"{url}/login")
        if page is not None and page.status == 200:
            return site_problems(page.headers, fetch(f"http://{urllib.parse.urlsplit(url).netloc}/login"))
        time.sleep(10)
    return [f"{url}/login did not answer with 200 within 100 seconds"]


# The environment azure in GitHub (MIT-44): only main may deploy, and only after your approval. The three IDs as
# environment secrets: not secret, but this way the public log of a run does not show them. Already there counts as fine.
def setup_github(github, client_id):
    print("\n🚀 GitHub: the environment azure, only for main, with you as the reviewer")
    me = gh("api", "user", "--jq", ".id")
    settings = {"reviewers": [{"type": "User", "id": int(me or 0)}],
                "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
    done = me is not None and gh("api", "-X", "PUT", f"repos/{github}/environments/azure", "--input", "-",
                                 stdin=json.dumps(settings)) is not None
    branches = gh("api", f"repos/{github}/environments/azure/deployment-branch-policies", "--jq", ".branch_policies[].name")
    if done and "main" not in (branches or "").split():
        done = gh("api", "-X", "POST", f"repos/{github}/environments/azure/deployment-branch-policies",
                  "-f", "name=main", "-f", "type=branch") is not None
    account = (az("account", "show", "--query", "[tenantId, id]", "-o", "tsv", ignore_error=True) or "").split()
    ids = dict(zip(("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"), [client_id, *account]))
    for name, value in ids.items():
        done = done and bool(value) and gh("secret", "set", name, "--env", "azure", "--repo", github, stdin=value) is not None
    if done:
        print("   ✅ Set: the next merge to main waits for your approval in the Actions tab, then goes to Azure")
    else:
        print("   ⚠️  Not everything worked; the app on Azure is fine. Set it by hand in Settings, Environments, azure:\n"
              "      only the branch main, yourself as required reviewer, and the secrets AZURE_CLIENT_ID\n"
              "      (terraform -chdir=terraform output -raw deploy_client_id), AZURE_TENANT_ID and AZURE_SUBSCRIPTION_ID.")


# Everything for Azure at once: the state storage if it is not there yet, the image GitHub built, and Terraform.
def run():
    check_tools("azure")
    # Without a sign-in nothing is possible; then first explain how, also for a tenant that requires MFA.
    account = az("account", "show", "--query", "[name, user.name]", "-o", "tsv", ignore_error=True)
    if account is None:
        stop(AZ_LOGIN_HELP, icon="🔐")
    subscription, login = (account.splitlines() + ["", ""])[:2]
    print(f"\n☁️  Signed in to Azure, subscription: {subscription}")

    # A merge on GitHub does not reach this folder by itself, and both the image tag and Terraform use what is checked
    # out here: deployed from an older branch, a fix that is already on main quietly stays off Azure (it happened once,
    # with an alert fix on 19-11-2026). Without a connection the fetch fails, and then this check is skipped.
    if git("fetch", "origin", "main") is not None and git("merge-base", "--is-ancestor", "origin/main", "HEAD") is None:
        stop("This folder is missing commits that are already on main on GitHub; a merge there does not come here by itself.\n"
             "   💡 Get them first:\n"
             "      git switch main\n"
             "      git pull\n"
             "   Then again: python scripts/deployment.py azure", icon="🔄")

    # Chicken and egg: Terraform needs somewhere for its state before it makes anything; a script sets that storage up once.
    if (REPO / "backend.conf").exists():
        print("🗄️  Storage for the Terraform state: already there (backend.conf)")
    else:
        print("\n🗄️  No storage for the Terraform state yet; setup_azure.py sets it up once now.")
        if subprocess.run([sys.executable, str(REPO / "scripts" / "setup_azure.py")], cwd=REPO).returncode != 0:
            sys.exit(1)

    # The tag is the content of app/ in your last commit (see CI-image.yml): a commit without an app change reuses it.
    github, tree = github_repo(), git("rev-parse", "HEAD:app")
    if not (github and tree):
        stop("No GitHub repo found (git remote get-url origin); the image comes from GitHub Actions.", icon="🤔")
    # ghcr.io wants lower case; the OIDC token of GitHub names the repo exactly as GitHub does (deploy.tf).
    repo, github = github.lower(), gh("repo", "view", github, "--json", "nameWithOwner", "--jq", ".nameWithOwner") or github
    tag = f"app-{tree}"
    print(f"\n📦 The image of app/ as in your last commit: ghcr.io/{repo}:{tag}")
    digest = image_digest(repo, tag)
    # By digest, like CD-azure.yml: the container app runs exactly this image, also after a cold start.
    image = f"ghcr.io/{repo}@{digest}"
    if not digest:
        stop("That image is not on ghcr.io yet, or it is not public.\n"
             "   💡 Put your last commit on main with a pull request and wait until the GitHub Action Image\n"
             "      is green after that, a few minutes:\n"
             f"      https://github.com/{repo}/actions\n"
             "   Then again: python scripts/deployment.py azure", icon="⏳")
    print(f"   ✅ Ready, and Container Apps may pull it: {digest}")
    # And signed by CI-image.yml on main, the image and its SBoM, as Deploy checks on GitHub. Without gh, or not signed
    # in to it, that cannot be checked here: then a warning, not a stop.
    if gh("auth", "status") is None:
        print("   ⚠️  Not checked whether GitHub signed this image: gh is missing or not signed in (gh auth login).")
    else:
        for kind in ("https://slsa.dev/provenance/v1", "https://cyclonedx.org/bom"):
            if gh("attestation", "verify", f"oci://{image}", "--repo", github, "--predicate-type", kind, "--source-ref",
                  "refs/heads/main", "--signer-workflow", f"{github}/.github/workflows/CI-image.yml") is None:
                stop(f"This image has no valid signature ({kind}) from CI-image.yml on main.\n"
                     "   An image only gets one when the GitHub Action Image runs on main, which it does on every push\n"
                     f"   there; or start it by hand: https://github.com/{repo}/actions/workflows/CI-image.yml\n"
                     "   Then again: python scripts/deployment.py azure", icon="🔏")
        print("   ✅ Signed by CI-image.yml on main: the image and its SBoM")

    print("\n🔧 Terraform: connecting to the state storage")
    # backend.conf is the only source: after a new bootstrap .terraform still knows the old storage, and then init stops
    # without -reconfigure. No state goes along; that belongs to the storage.
    if not terraform("init", "-input=false", "-reconfigure", "-backend-config=../backend.conf"):
        stop("terraform init did not work; the message is above.")
    # What the previous deployment left in the state, read once: the Blue Teamers, deploying from GitHub, the mail rule.
    before = outputs()

    hack = hackmode() if deployment.INTERACTIVE else {"THROTTLE_IP_MODE": None, "THROTTLE_PAIR_EXEMPT_USERS": None}
    # The mail on a lockout (alerts.tf): by default the address you signed in to az with. Not in the repo, which is public.
    email = login if re.fullmatch(EMAIL, login) else ""
    # The Blue Teamers get the same mail (UC-11). A new run offers the same ones again, so they are not dropped.
    blue = before.get("blue_team_emails") or "-"
    if deployment.INTERACTIVE:
        print("\n📧 On a lockout Azure sends a mail within a few minutes.")
        email = ask("To which address?", email or "-", EMAIL)
        blue = ask("Extra addresses for the Blue Teamers, separated by commas (- for none)", blue, EMAILS)
    if not re.fullmatch(EMAIL, email):
        stop("No email address for the alert; run this script in a terminal and fill one in.", icon="📧")
    blue = [] if blue == "-" else blue.split(",")
    # Deploying from GitHub (MIT-44): once on, it stays on, also without gh; undo removes it. Otherwise only with gh.
    signed_in = gh("auth", "status") is not None
    from_github = bool(before.get("deploy_client_id"))
    if from_github:
        print("\n🚀 Deploying from GitHub after your approval: on, and it stays on")
    elif deployment.INTERACTIVE and signed_in:
        from_github = yes("\n🚀 Deploy from GitHub after a merge, only once you approve it in the Actions tab (MIT-44)?")
    # Exactly as the token of a job names the repo; with immutable subjects that includes the IDs of owner and repo.
    oidc = gh("api", f"repos/{github}/actions/oidc/customization/sub", "--jq", ".sub_claim_prefix // empty") or f"repo:{github}"
    variables = [f"app_image={image}", f"alert_email={email}", f"github_oidc_prefix={oidc}",
                 f"deploy_from_github={'true' if from_github else 'false'}", f"blue_team_emails={json.dumps(blue)}"]
    if region := state_region():
        variables.append(f"location={region}")
    if hack["THROTTLE_IP_MODE"]:
        variables += ["throttle_ip_mode=hackweek", "min_replicas=1"]
    if hack["THROTTLE_PAIR_EXEMPT_USERS"]:
        variables.append(f"throttle_pair_exempt_users={hack['THROTTLE_PAIR_EXEMPT_USERS']}")

    # Before Terraform, because its plan already reads the Key Vault secrets while you decide on yes; and again after
    # it, so a slow yes or a long apply still has the full window behind it.
    mute_own_alerts(before.get("deploy_mute_rule_id"), announce=False)
    print("\n🏗️  Terraform. It first shows what it is going to do, and only starts when you type yes.\n")
    # The question for yes stays: this turns on resources that cost money.
    if not terraform("apply", *(f"-var={v}" for v in variables)):
        stop("terraform apply did not work, or you did not type yes; the message is above.")
    # And what this deployment left in the state, read once: the address, the mail rule, the identity for GitHub.
    after = outputs()
    mute_own_alerts(after.get("deploy_mute_rule_id"))
    check_schema_job()
    url = after.get("app_url", "")
    if from_github and signed_in:
        setup_github(github, after.get("deploy_client_id", ""))
    print("\n🔎 On Azure: HTTPS, the headers and the session cookie")
    if not url:
        print("   ⚠️  No address in the Terraform output, so not checked.")
    elif problems := live_problems(url):
        stop(f"The app is on {url}, but on Azure:\n" + "\n".join(f"   ❌ {p}" for p in problems) +
             "\n   💡 What decides this: HTTPS_ONLY and the ingress in terraform/app.tf, the headers in app/app.py.")
    else:
        print("   ✅ HTTP goes to HTTPS (301), HSTS, CSP, nosniff, no-store, and __Host-session with Secure, HttpOnly,\n"
              "      SameSite=Lax, Path=/ and no Domain")
    print(f"\n🎉 Done! The app is on {url}")
    print("💡 Updating: merge a pull request to main, and approve the deployment in the Actions tab; without GitHub set up,\n"
          "   wait until the Action Image is green and run this script again.")
    print("💡 Everything gone again, so it costs nothing: python scripts/deployment.py undo\n")
