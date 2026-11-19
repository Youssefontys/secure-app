# The security log (MIT-31) kept on Azure: Container Apps puts stdout and stderr of the app in this workspace (MC-28).
# The app itself cannot reach it: whoever takes over the container can no longer wipe the log.
resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${local.unique}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  # The IP address and username are personal data (A-11): 30 days and then really gone, not a day later.
  retention_in_days                       = 30
  immediate_data_purge_on_30_days_enabled = true
  # A brake on the cost, not a filter: collecting stops until the next day once this is hit, with nothing
  # telling you it happened. 0.1 was fine day to day, but the hacking week is exactly the time both the real
  # log volume and the value of not going blind are highest; 1 GB leaves ten times the room for a few euros.
  daily_quota_gb = 1
  tags           = local.tags
}
