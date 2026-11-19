# A mail on a lockout (MIT-37, MC-28): keeping the log is not enough, someone must also see it.
resource "azurerm_monitor_action_group" "security" {
  name                = "ag-${local.name}-security"
  resource_group_name = azurerm_resource_group.main.name
  short_name          = "notes"
  tags                = local.tags

  email_receiver {
    name                    = "admin"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }

  # The Blue Teamers (UC-11): the same mail as the administrator. They only read the mail; the log itself stays with the administrator.
  dynamic "email_receiver" {
    for_each = var.blue_team_emails
    content {
      name                    = "blue-${email_receiver.key + 1}"
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }
}

# What gets a mail, each a query on the log of the app in Log Analytics: what it means, the query, over how long, and
# from how many lines. A new alert is one line here. The first one is the lockout of MIT-37; the others are for what a
# lockout does not show (MC-28): a value that does not decrypt, an error someone provokes, and failed logins spread
# over more addresses or names than one counter sees.
locals {
  log = "ContainerAppConsoleLogs_CL | where Log_s has"
  alerts = {
    lockout = {
      description = "A counter of the attempt limits was locked (lockout_started, MIT-10)."
      query       = "${local.log} \"lockout_started\""
      window      = "PT5M"
      above       = 0
    }
    unreadable = {
      description = "A stored value did not decrypt: changed or moved in the database, or another key (note_unreadable, MC-08, MC-23)."
      query       = "${local.log} \"note_unreadable\""
      window      = "PT5M"
      above       = 0
    }
    error = {
      description = "The app logged an unexpected error (MIT-25, MC-26)."
      query       = "${local.log} \"Unexpected error\""
      window      = "PT5M"
      above       = 0
    }
    # More than one address can do before it is locked (20, in hackmode 100): so several addresses, or many names.
    failed-logins = {
      description = "More failed logins in 15 minutes than one address can make before it is locked (login_failed, MC-03)."
      query       = "${local.log} \"login_failed\""
      window      = "PT15M"
      above       = var.throttle_ip_mode == "hackweek" ? 120 : 25
    }
    # AZKVAuditLogs, the resource-specific table from the diagnostic settings in keyvault.tf: a SecretGet by
    # anyone other than the app's own identity (the vault) or the schema job's identity (the owner's vault).
    # Identity is a JSON string, not a flat field (checked against a real VaultGet row on 18-11-2026, after the
    # first apply); the object id sits under claim."http://schemas.microsoft.com/identity/claims/objectidentifier".
    keyvault-read = {
      description = "A Key Vault secret was read by something other than the app's own identity (MC-22, MC-28)."
      query       = "AZKVAuditLogs | where OperationName == \"SecretGet\" | extend caller = tostring(parse_json(Identity).claim[\"http://schemas.microsoft.com/identity/claims/objectidentifier\"]) | where caller !in (\"${azurerm_user_assigned_identity.app.principal_id}\", \"${azurerm_user_assigned_identity.schema.principal_id}\")"
      window      = "PT15M"
      above       = 0
    }
    # Container Apps puts its own events in a second table, ContainerAppSystemLogs_CL: a cold start alone makes
    # ProbeFailed (the readiness probe, before Gunicorn is up) and a successful one-shot job container both
    # Warning, in about half of all cold starts (measured over 43 events, two days, 17-11-2026 and 18-11-2026);
    # neither is a problem. What is left after excluding both is a real, unplanned one, such as the platform's own
    # "RevisionFailure" seen once in that same measurement.
    restart = {
      description = "A replica of the container app had an unplanned problem (not a cold start warming up, not a job container exiting cleanly)."
      query       = "ContainerAppSystemLogs_CL | where Type_s == \"Warning\" | where Reason_s != \"ProbeFailed\" | where not(Log_s has \"exit code '0'\")"
      window      = "PT15M"
      above       = 0
    }
  }
}

# Every 5 minutes (€1.32 per month per alert): a line only shows up in Log Analytics after a few minutes, so looking more often helps little.
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "security" {
  for_each             = local.alerts
  name                 = "alert-${local.name}-${each.key}"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  scopes               = [azurerm_log_analytics_workspace.main.id]
  description          = each.value.description
  severity             = 2
  evaluation_frequency = "PT5M"
  window_duration      = each.value.window
  # Do not mail again every 5 minutes during one attack.
  mute_actions_after_alert_duration = "PT1H"
  # In a new workspace the table only exists after the first log line; otherwise Azure refuses the rule at creation.
  skip_query_validation = true
  tags                  = local.tags

  # An own identity, as Microsoft recommends; without it the rule reads with the rights of whoever changed it last.
  identity {
    type = "SystemAssigned"
  }

  criteria {
    query                   = each.value.query
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = each.value.above
  }

  action {
    action_groups = [azurerm_monitor_action_group.security.id]
  }
}

# Only reading in this one workspace, per alert.
resource "azurerm_role_assignment" "alert_reader" {
  for_each             = azurerm_monitor_scheduled_query_rules_alert_v2.security
  scope                = azurerm_log_analytics_workspace.main.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = each.value.identity[0].principal_id
}

# Creating this alert right after the role assignments is not enough: that only orders when Terraform creates
# things, not when the assignment's own "Succeeded" event has actually travelled through Azure's activity-log
# stream relative to when the alert starts evaluating. On a from-scratch deploy, with ~11 assignments landing
# within a couple of seconds of each other, the alert caught a chunk of its own first batch (11 mails,
# 19-11-2026). A real wait fixes the race a depends_on on the resources themselves cannot.
resource "time_sleep" "role_assignments_settled" {
  depends_on = [
    azurerm_role_assignment.alert_reader,
    azurerm_role_assignment.app_secrets,
    azurerm_role_assignment.deploy,
    azurerm_role_assignment.kv_operator,
    azurerm_role_assignment.schema_secrets,
  ]
  create_duration = "15m"
}

# A role assigned anywhere in the subscription (MC-31): whoever has the sign-in of the administrator can give themselves
# any role, and this is where that shows. From the activity log of Azure, not from the log of the app, and free.
# Only Succeeded: Azure logs every assignment twice, Started and Succeeded, and an activity log alert mails on every
# event. Only created once the wait above is over, so the first apply does not mail its own; a later
# apply that assigns a role does, and that mail is your own.
resource "azurerm_monitor_activity_log_alert" "roles" {
  name                = "alert-${local.name}-roles"
  resource_group_name = azurerm_resource_group.main.name
  location            = "global"
  scopes              = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}"]
  description         = "A role was assigned in the subscription (MC-31)."
  tags                = local.tags

  depends_on = [time_sleep.role_assignments_settled]

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Authorization/roleAssignments/write"
    statuses       = ["Succeeded"]
  }

  action {
    action_group_id = azurerm_monitor_action_group.security.id
  }
}

# A mail per 25% of a small monthly budget (#21): not a security event, but a run-away cost (a mistake in Terraform,
# or someone else using the subscription) should not go unnoticed either. 20 euros in steps of 5, actual spend, not
# forecasted. The start date is fixed at the first of the month this was set up; cost data itself lags about a day,
# so the thresholds are a configuration decision here, not something this deployment can prove by forcing it.
resource "azurerm_consumption_budget_resource_group" "main" {
  name              = "budget-${local.name}"
  resource_group_id = azurerm_resource_group.main.id

  amount     = 20
  time_grain = "Monthly"

  time_period {
    start_date = "2026-11-01T00:00:00Z"
  }

  dynamic "notification" {
    for_each = [25, 50, 75, 100]
    content {
      threshold      = notification.value
      operator       = "GreaterThanOrEqualTo"
      contact_groups = [azurerm_monitor_action_group.security.id]
    }
  }
}
