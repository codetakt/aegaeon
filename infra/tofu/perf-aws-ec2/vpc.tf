data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "perf" {
  count = var.create_vpc ? 1 : 0

  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "perf" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.perf[0].id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

resource "aws_subnet" "perf_public" {
  count = var.create_vpc ? 1 : 0

  vpc_id                  = aws_vpc.perf[0].id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = coalesce(var.availability_zone, data.aws_availability_zones.available.names[0])
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-public-subnet"
  }
}

resource "aws_route_table" "perf_public" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.perf[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.perf[0].id
  }

  tags = {
    Name = "${var.name_prefix}-public-rt"
  }
}

resource "aws_route_table_association" "perf_public" {
  count          = var.create_vpc ? 1 : 0
  subnet_id      = aws_subnet.perf_public[0].id
  route_table_id = aws_route_table.perf_public[0].id
}
