######################################################################
# GAP-05: put the intake Lambda inside the starter's VPC, behind a
# hardened security group. Private subnets have no route to the
# internet or AWS services by default, so this file also gives them a
# route table plus VPC endpoints (S3/DynamoDB gateway, CloudWatch Logs
# interface) so the Lambda keeps working without a NAT gateway.
######################################################################

resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg-${local.suffix}"
  description = "Intake Lambda ENIs: no inbound, HTTPS-only outbound"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to AWS services via VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-lambda-sg" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${local.name_prefix}-s3-endpoint" }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${local.name_prefix}-dynamodb-endpoint" }
}

resource "aws_security_group" "vpc_endpoints" {
  name        = "${local.name_prefix}-vpce-sg-${local.suffix}"
  description = "Interface VPC endpoints: HTTPS inbound from the Lambda SG only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTPS from the intake Lambda"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
  }

  tags = { Name = "${local.name_prefix}-vpce-sg" }
}

resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = { Name = "${local.name_prefix}-logs-endpoint" }
}
