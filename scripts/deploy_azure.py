# Deploying on Azure: the state storage if it is not there yet (setup_azure.py), the image GitHub built,
# Terraform, and if you want, deploying from GitHub after your approval (MIT-44). Start through deployment.py.

import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import deployment
from deployment import REPO, ask, check_tools, gh, git, github_repo, hackmode, stop, terraform, yes

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


# One output of Terraform as text; "" if it is not there (no state yet, or null).
def output(name):
    result = subprocess.run([shutil.which("terraform"), "-chdir=terraform", "output", "-raw", name],
                            cwd=REPO, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


# The app follows wherever the state storage actually lives, read live from Azure: one real source, instead of a
# second region (variables.tf's own default) that only matches by coincidence. "" if backend.conf or the group is gone.
def state_region():
    conf = (REPO / "backend.conf").read_text(encoding="utf-8")
    match = re.search(r'resource_group_name\s*=\s*"([^"]+)"', conf)
    if not match:
        return ""
    result = subprocess.run([shutil.which("az"), "group", "show", "--name", match.group(1), "--query", "location", "-o", "tsv"],
                            capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


# Opens the window of the rule that holds back the mails a deploy causes itself, from now on for MUTE_MINUTES. Before
# the first apply the rule does not exist yet, and Terraform gives it a first window itself. A failure only costs a
# mail about your own deploy, so it warns instead of stopping. Returns the rule's id, so the second opening does not
# ask Terraform again: every terraform output fetches the state from Azure, about half a minute.
def mute_own_alerts(rule_id=""):
    rule_id = rule_id or output("deploy_mute_rule_id")
    if not rule_id:
        return ""
    az, url = shutil.which("az"), f"https://management.azure.com{rule_id}?api-version=2021-08-08"
    got = subprocess.run([az, "rest", "--method", "get", "--url", url], capture_output=True, text=True)
    if got.returncode == 0:
        rule = json.loads(got.stdout)
        start = datetime.now(timezone.utc)
        until = start + timedelta(minutes=MUTE_MINUTES)
        rule["properties"]["schedule"] = {"effectiveFrom": f"{start:%Y-%m-%dT%H:%M:%S}",
                                          "effectiveUntil": f"{until:%Y-%m-%dT%H:%M:%S}", "timeZone": "UTC"}
        # As a file: az is a .cmd on Windows, and cmd.exe mangles the quotes of JSON on the command line.
        with tempfile.TemporaryDirectory() as folder:
            body = Path(folder) / "rule.json"
            body.write_text(json.dumps({key: rule[key] for key in ("location", "tags", "properties") if key in rule}),
                            encoding="utf-8")
            put = subprocess.run([az, "rest", "--method", "put", "--url", url, "--body", f"@{body}"],
                                 capture_output=True, text=True)
        if put.returncode == 0:
            print(f"🔕 Mails about this deploy itself (Key Vault reads, a new revision, roles) held back until "
                  f"{until.astimezone():%H:%M}")
            return rule_id
    print("⚠️  Could not hold back the mails about this deploy itself; a mail from the Key Vault alert may follow.")
    return rule_id


# The outputs at the end, in the order of outputs.tf: what you use yourself, a blank line, then what only this script
# uses. One call for all of them: every terraform output fetches the state from Azure again. The Blue Teamers only as
# a count: personal data, which is why Terraform marks the output sensitive too.
def summary(blue):
    result = subprocess.run([shutil.which("terraform"), "-chdir=terraform", "output", "-json"],
                            cwd=REPO, capture_output=True, text=True)
    values = {name: item["value"] for name, item in json.loads(result.stdout).items()} if result.returncode == 0 else {}
    lines = [("app_url", values.get("app_url")),
             ("blue_team_emails", f"{len(blue)} address(es), not shown: personal data" if blue else "none"),
             ("security_log_command", values.get("security_log_command")),
             None,
             ("deploy_client_id", values.get("deploy_client_id") or "none: deploying from GitHub is off"),
             ("deploy_mute_rule_id", values.get("deploy_mute_rule_id"))]
    for line in lines:
        print(f"   {line[0]:<20} = {line[1]}" if line else "")


# The environment azure in GitHub (MIT-44): only main may deploy, and only after your approval. The three IDs as
# environment secrets: not secret, but this way the public log of a run does not show them. Already there counts as fine.
def setup_github(github):
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
    account = subprocess.run([shutil.which("az"), "account", "show", "--query", "[tenantId, id]", "-o", "tsv"],
                             capture_output=True, text=True).stdout.split()
    ids = dict(zip(("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"), [output("deploy_client_id"), *account]))
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
    account = subprocess.run([shutil.which("az"), "account", "show", "--query", "[name, user.name]", "-o", "tsv"],
                             capture_output=True, text=True)
    if account.returncode != 0:
        stop(AZ_LOGIN_HELP, icon="🔐")
    subscription, login = (account.stdout.splitlines() + ["", ""])[:2]
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

    hack = hackmode() if deployment.INTERACTIVE else {"THROTTLE_IP_MODE": None, "THROTTLE_PAIR_EXEMPT_USERS": None}
    # The mail on a lockout (alerts.tf): by default the address you signed in to az with. Not in the repo, which is public.
    email = login if re.fullmatch(EMAIL, login) else ""
    # The Blue Teamers get the same mail (UC-11). A new run offers the same ones again, so they are not dropped.
    blue = output("blue_team_emails") or "-"
    if deployment.INTERACTIVE:
        print("\n📧 On a lockout Azure sends a mail within a few minutes.")
        email = ask("To which address?", email or "-", EMAIL)
        blue = ask("Extra addresses for the Blue Teamers, separated by commas (- for none)", blue, EMAILS)
    if not re.fullmatch(EMAIL, email):
        stop("No email address for the alert; run this script in a terminal and fill one in.", icon="📧")
    blue = [] if blue == "-" else blue.split(",")
    print("\n🏗️  Terraform. It first shows what it is going to do, and only starts when you type yes.\n")
    # backend.conf is the only source: after a new bootstrap .terraform still knows the old storage, and then init stops
    # without -reconfigure. No state goes along; that belongs to the storage.
    if not terraform("init", "-input=false", "-reconfigure", "-backend-config=../backend.conf"):
        stop("terraform init did not work; the message is above.")
    # Deploying from GitHub (MIT-44): once on, it stays on, also without gh; undo removes it. Otherwise only with gh.
    signed_in = gh("auth", "status") is not None
    from_github = bool(output("deploy_client_id"))
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
    rule_id = mute_own_alerts()
    # The question for yes stays: this turns on resources that cost money.
    if not terraform("apply", *(f"-var={v}" for v in variables)):
        stop("terraform apply did not work, or you did not type yes; the message is above.")
    mute_own_alerts(rule_id)
    if from_github and signed_in:
        setup_github(github)
    print("\n🎉 Done!\n")
    summary(blue)
    print("\n⏳ Terraform has started the schema job; if logging in gives an error in the first minute, try again shortly.")
    print("💡 Updating: merge a pull request to main, and approve the deployment in the Actions tab; without GitHub set up,\n"
          "   wait until the Action Image is green and run this script again.")
    print("💡 Everything gone again, so it costs nothing: python scripts/deployment.py undo\n")
