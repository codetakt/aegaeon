locals {
  ecr_repositories = {
    migrate = "${var.name_prefix}/migrate"
    server  = "${var.name_prefix}/server"
  }
}

resource "aws_ecr_repository" "image" {
  for_each = var.create_ecr_repositories ? local.ecr_repositories : {}

  name                 = each.value
  image_tag_mutability = var.ecr_image_tag_mutability
  force_delete         = var.ecr_force_delete

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "image" {
  for_each = aws_ecr_repository.image

  repository = each.value.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged intermediate images"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep the most recent staging evidence images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.ecr_retain_image_count
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
