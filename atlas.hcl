variable "database_url" {
  type    = string
  default = getenv("DATABASE_URL")
}

variable "dev_database_url" {
  type    = string
  default = "docker://postgres/18.1/dev"
}

env "local" {
  src = "file://db/schema.sql"
  url = var.database_url
  dev = var.dev_database_url

  migration {
    dir = "file://db/migrations"
  }
}
