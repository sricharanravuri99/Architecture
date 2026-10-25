output "firewall_arn"        { value = aws_networkfirewall_firewall.main.arn }
output "firewall_id"         { value = aws_networkfirewall_firewall.main.id }
output "endpoint_ids"        { value = aws_networkfirewall_firewall.main.firewall_status[0].sync_states }
