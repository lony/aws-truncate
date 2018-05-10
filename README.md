aws-truncate
===

This Python3 script truncates your existing AWS account by deleting each individual resource in every region interactively.

# Supported

```
    "cloudformation":           True,
    "apigateway":               True,
    "iot":                      True,
    "elasticbeanstalk":         True,
    "lambda":                   True,
    "ec2":                      True,
        "ec2-elb":              True,
        "ec2-autoscaling":      True,
        "ec2-instance":         True,
        "ec2-volumes":          True,
        "ec2-security-group":   True,
        "ec2-eip":              True,
        "ec2-images":           True,
        "ec2-keypairs":         True,
        "ec2-snapshots":        True,
    "s3":                       True,
    "dynamodb":                 True,
    "rds":                      True,
    "iam":                      True,
        "iam-group":            True,
        "iam-user":             True,
        "iam-role":             True,
        "iam-policy":           True,
```

# Getting started

1. Run `virtualenv -p /usr/local/bin/python3 venv --no-site-packages`
2. Run `source venv/bin/activate`
3. Run `pip install -r requirements.txt`

**WARNING: This will delete resources forever! You should understand what you are doing if you confirm.**

4. Run `./aws_truncate.py`

... and follow the instructions.

# Inspired by

* https://github.com/cloudetc/awsweeper
