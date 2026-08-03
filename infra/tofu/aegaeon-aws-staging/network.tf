resource "aws_vpc" "main" {
  count = var.create_vpc ? 1 : 0

  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.main[0].id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  for_each = var.create_vpc ? { for index, az in local.azs : az => index } : {}

  vpc_id                  = aws_vpc.main[0].id
  availability_zone       = each.key
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, each.value)
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-public-${each.key}"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  for_each = var.create_vpc ? { for index, az in local.azs : az => index } : {}

  vpc_id            = aws_vpc.main[0].id
  availability_zone = each.key
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, each.value + var.availability_zone_count)

  tags = {
    Name = "${var.name_prefix}-private-${each.key}"
    Tier = "private"
  }
}

locals {
  nat_subnet_ids = (
    var.create_vpc && var.enable_nat_gateway
    ? (
      var.nat_gateway_mode == "per_az"
      ? { for az, subnet in aws_subnet.public : az => subnet.id }
      : { single = values(aws_subnet.public)[0].id }
    )
    : {}
  )
}

resource "aws_eip" "nat" {
  for_each = local.nat_subnet_ids

  domain = "vpc"

  tags = {
    Name = "${var.name_prefix}-nat-${each.key}"
  }
}

resource "aws_nat_gateway" "main" {
  for_each = local.nat_subnet_ids

  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = each.value

  tags = {
    Name = "${var.name_prefix}-nat-${each.key}"
  }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }

  tags = {
    Name = "${var.name_prefix}-public"
  }
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  for_each = aws_subnet.private

  vpc_id = aws_vpc.main[0].id

  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []

    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.main[var.nat_gateway_mode == "per_az" ? each.key : "single"].id
    }
  }

  tags = {
    Name = "${var.name_prefix}-private-${each.key}"
  }
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}
