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

# A role assigned anywhere in the subscription (MC-31): whoever has the sign-in of the administrator can give themselves
# any role, and this is where that shows. From the activity log of Azure, not from the log of the app, and free.
# Terraform assigns roles itself too: a mail right after an apply is your own.
resource "azurerm_monitor_activity_log_alert" "roles" {
  name                = "alert-${local.name}-roles"
  resource_group_name = azurerm_resource_group.main.name
  location            = "global"
  scopes              = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}"]
  description         = "A role was assigned in the subscription (MC-31)."
  tags                = local.tags

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Authorization/roleAssignments/write"
  }

  action {
    action_group_id = azurerm_monitor_action_group.security.id
  }
}
