resource "aws_cloudwatch_log_metric_filter" "route_table_changes_metric_filter" {
  name           = "RouteTableChanges"
  pattern        = "{ ($.eventName = CreateRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
  log_group_name = aws_cloudwatch_log_group.CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "RouteTableChanges"
    namespace = "Metric_Alarm_Namespace"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "route_table_changes_cw_alarm" {
  alarm_name                = "RouteTableChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.route_table_changes_metric_filter.id
  namespace                 = "Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = [aws_sns_topic.Alerts_SNS_Topic.arn]
  insufficient_data_actions = []
}
