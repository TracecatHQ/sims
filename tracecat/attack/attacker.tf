provider "aws" {}

variable "allowed_aws_region" {
  description = "The AWS region where the user and role are allowed to operate"
  type        = string
}

data "aws_caller_identity" "current" {}

resource "aws_iam_user" "tracecat_lab_admin_attacker" {
  name = "tracecat-lab-admin-attacker"
}

resource "aws_iam_role" "allowed_region_admin_role" {
  name                 = "tracecat-lab-admin-attacker-role"
  max_session_duration = 3600 # 1 hour in seconds

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${aws_iam_user.tracecat_lab_admin_attacker.name}"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    owner = "tracecat",
    role  = "admin"
  }
}

resource "aws_iam_role_policy" "region_restriction" {
  name   = "RegionRestriction"
  role   = aws_iam_role.allowed_region_admin_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "*",
        Resource = "*",
        Condition = {
          StringEquals = {
            "aws:RequestedRegion": var.allowed_aws_region
          }
        }
      }
    ]
  })
}

resource "aws_iam_user_policy" "allow_assume_admin_role" {
  name = "AllowAssumeAdminRole"
  user = aws_iam_user.tracecat_lab_admin_attacker.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "sts:AssumeRole",
        Resource = aws_iam_role.allowed_region_admin_role.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_policy_attachment" {
  role       = aws_iam_role.allowed_region_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "normal" {
  user = "${aws_iam_user.tracecat_lab_admin_attacker.name}"
}

resource "aws_iam_access_key" "compromised" {
  user = "${aws_iam_user.compromised.name}"
}

resource "local_file" "credentials" {
  content  = jsonencode({
    normal = {
      redpanda = {
        aws_access_key_id = "${aws_iam_access_key.normal.id}"
        aws_secret_access_key = "${aws_iam_access_key.normal.secret}"
      }
    }
    compromised = {
      redpanda = {
        aws_access_key_id = "${aws_iam_access_key.compromised.id}"
        aws_secret_access_key = "${aws_iam_access_key.compromised.secret}"
      }
    }
  })
  filename = "credentials.json"
}
