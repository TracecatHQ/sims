provider "aws" {}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "aws_iam_user" "tracecat_lab_admin" {
  name = "tracecat-lab-admin"
}

resource "aws_iam_user_policy_attachment" "admin_policy_attachment" {
  user       = aws_iam_user.tracecat_lab_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "normal" {
  user = aws_iam_user.tracecat_lab_admin.name
}

resource "aws_iam_access_key" "compromised" {
  user = aws_iam_user.tracecat_lab_admin.name
}

resource "local_file" "credentials" {
  content  = jsonencode({
    normal = {
      redpanda = {
        aws_access_key_id     = aws_iam_access_key.normal.id
        aws_secret_access_key = aws_iam_access_key.normal.secret
      }
    },
    compromised = {
      redpanda = {
        aws_access_key_id     = aws_iam_access_key.compromised.id
        aws_secret_access_key = aws_iam_access_key.compromised.secret
      }
    }
  })
  filename = "credentials.json"
}
