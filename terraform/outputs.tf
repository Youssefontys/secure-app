output "app_url" {
  value = "https://${azurerm_container_app.app.ingress[0].fqdn}"
}

# For deploy_azure.py, so that a new run offers the same Blue Teamers again instead of dropping them. Personal data, so sensitive.
output "blue_team_emails" {
  value     = join(",", var.blue_team_emails)
  sensitive = true
}

# The lockouts of the last day from the kept log; the lines arrive a few minutes after they happen.
output "security_log_command" {
  value = "az monitor log-analytics query --workspace ${azurerm_log_analytics_workspace.main.workspace_id} --analytics-query \"ContainerAppConsoleLogs_CL | where TimeGenerated > ago(1d) and Log_s has 'lockout_started' | project TimeGenerated, Log_s\" -o table"
}

# For the environment azure in GitHub (deploy_azure.py): the identity the deploy job signs in as. Not a secret.
# null without deploy_from_github.
output "deploy_client_id" {
  value = one(azurerm_user_assigned_identity.deploy[*].client_id)
}

# For deploy_azure.py, which opens the window of this rule around every deploy (alerts.tf).
output "deploy_mute_rule_id" {
  value = azurerm_monitor_alert_processing_rule_suppression.deploy.id
}
