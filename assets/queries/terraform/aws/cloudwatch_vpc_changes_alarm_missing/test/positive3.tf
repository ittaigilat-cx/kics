resource "aws_cloudwatch_log_metric_filter" "VPC_Changes_Metric_Filter" {
  name           = "VPCChanges"
  pattern        = "{ ($.eventName = CreateVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = EnableVpcClassicLink) }"
  log_group_name = aws_cloudwatch_log_group.CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "VPCChanges"
    namespace = "Metric_Alarm_Namespace"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "VPC_Changes_CW_Alarm" {
  alarm_name                = "VPCChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.VPC_Changes_Metric_Filter.id
  namespace                 = "Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to VPC will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = [aws_sns_topic.Alerts_SNS_Topic.arn]
  insufficient_data_actions = []
}
