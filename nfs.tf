provider "aws" {
region = "ap-south-1"
profile = "aks07"
}

resource "aws_vpc" "tf_vpc" {
  cidr_block       = "192.168.0.0/16"
  instance_tenancy = "default"
  enable_dns_hostnames = "true"
  tags = {
    Name = "myvpc2"
  }
}

resource "aws_subnet" "tf_subnet" {
  vpc_id     = aws_vpc.tf_vpc.id
  cidr_block = "192.168.0.0/24"
  availability_zone = "ap-south-1a"
  map_public_ip_on_launch = "true"

  tags = {
    Name = "sub1"
  }
}


//Creation of Security-Groups

resource "aws_security_group" "security" {
name = "nfs_firewall"
vpc_id = aws_vpc.tf_vpc.id
description = "allow NFS"

ingress {
description = "NFS"
from_port = 2049
to_port = 2049
protocol = "tcp"
cidr_blocks = [ "0.0.0.0/0" ]
}

ingress {
description = "HTTP"
from_port = 80
to_port = 80
protocol = "tcp"
cidr_blocks = [ "0.0.0.0/0" ]
}

ingress {
description = "SSH"
from_port = 22
to_port = 22
protocol = "tcp"
cidr_blocks = [ "0.0.0.0/0" ]
}

egress {
from_port= 0
to_port = 0
protocol = "-1"
cidr_blocks = [ "0.0.0.0/0" ]
}

tags = {
Name = "firewall_nfs"
}
}

resource "aws_efs_file_system" "tf_efs" {
creation_token = "efs"

tags = {
Name = "myefs"
}
}


resource "aws_efs_mount_target" "efsmount" {
file_system_id = aws_efs_file_system.tf_efs.id
subnet_id = aws_subnet.tf_subnet.id
security_groups = [ aws_security_group.security.id ]
}

resource "aws_internet_gateway" "tf_gw" {
  vpc_id = aws_vpc.tf_vpc.id

  tags = {
    Name = "my_ig"
  }
}

resource "aws_route_table" "tf_rt" {
  vpc_id = aws_vpc.tf_vpc.id

  route {
    
gateway_id = aws_internet_gateway.tf_gw.id
    cidr_block = "0.0.0.0/0"
  }

    tags = {
    Name = "my_rt2"
  }
}

resource "aws_route_table_association" "tf_sub_a" {
  subnet_id      = aws_subnet.tf_subnet.id
  route_table_id = aws_route_table.tf_rt.id
}


resource "aws_instance" "myin" {
depends_on = [ aws_efs_mount_target.efsmount ]
ami = "ami-0447a12f28fddb066"
instance_type = "t2.micro"
key_name = "key"
subnet_id = aws_subnet.tf_subnet.id
vpc_security_group_ids = [ aws_security_group.security.id ]

user_data = <<-EOF
      #! /bin/bash
      
       sudo yum install httpd -y
       sudo systemctl start httpd 
       sudo systemctl enable httpd
       sudo rm -rf /var/www/html/*
       sudo yum install -y amazon-efs-utils
       sudo apt-get -y install amazon-efs-utils
       sudo yum install -y nfs-utils
       sudo apt-get -y install nfs-common
       sudo file_system_id_1="${aws_efs_file_system.tf_efs.id}
       sudo efs_mount_point_1="/var/www/html"
       sudo mkdir -p "$efs_mount_point_1"
       sudo test -f "/sbin/mount.efs" && echo "$file_system_id_1:/ $efs_mount_point_1 efs tls,_netdev" >> /etc/fstab || echo "$file_system_id_1.efs.ap-south-1.amazonaws.com:/$efs_mount_point_1 nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport,_netdev 0 0" >> /etc/fstab
       sudo test -f "/sbin/mount.efs" && echo -e "\n[client-info]\nsource=liw"   >> /etc/amazon/efs/efs-utils.conf
       sudo mount -a -t efs,nfs4 defaults
       cd /var/www/html
       sudo yum insatll git -y
       sudo mkfs.ext4 /dev/xvdf1
       sudo rm -rf /var/www/html/*
       sudo yum install git -y
       sudo git clone https://github.com/whoaks/aws_task2.git /var/www/html
     
     EOF

tags = {
Name = "os_efs"
}
}

resource "aws_s3_bucket" "bucket" {

bucket = "aks4321"
acl = "public-read"
force_destroy = true
policy = <<EOF
{
  "Id": "MakePublic",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetObject"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::aks4321/*",
      "Principal": "*"
    }
  ]
}
EOF


tags = {
Name = "aks4321"
}
}

 
//Block Public Access


resource "aws_s3_bucket_public_access_block" "s3block" {

bucket = aws_s3_bucket.bucket.id
block_public_policy = true
}

locals {
s3_origin_id = "S3-${aws_s3_bucket.bucket.bucket}"
}


//Creation Of CloudFront


resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
comment = "bucket_aks"
}

resource "aws_cloudfront_distribution" "cloudfront" {
    origin {
        domain_name = aws_s3_bucket.bucket.bucket_regional_domain_name
        origin_id = local.s3_origin_id
 
        s3_origin_config {

origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
}
}
 enabled = true
is_ipv6_enabled = true
comment = "access"


    default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = local.s3_origin_id

        # Forward all query strings, cookies and headers
        forwarded_values {
            query_string = false
        
        cookies {
	forward = "none"
            }
        }

        viewer_protocol_policy = "allow-all"
        min_ttl = 0
        default_ttl = 3600
        max_ttl = 86400
    }
# Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }
    # Restricts who is able to access this content
    restrictions {
        geo_restriction {
            # type of restriction, blacklist, whitelist or none
            restriction_type = "none"
        }
    }

    # SSL certificate for the service.
    viewer_certificate {
        cloudfront_default_certificate = true
    }
retain_on_delete = true

}


resource "aws_codepipeline" "codepipeline" {
  name     = "diyaksh"
  role_arn = "arn:aws:iam::341111******:role/service-role/AWSCodePipelineServiceRole-ap-south-1-diyaksh"


   artifact_store {
    location = "${aws_s3_bucket.bucket.bucket}"
    type     = "S3"
	}
	 
	 stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      output_artifacts = ["SourceArtifacts"]
configuration = {
        Owner  = "whoaks"
        Repo   = "aws_task2"
        Branch = "master"
	OAuthToken = "a962d286561fb7eeae716f2ecee9d258ac141042"        
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "S3"
      version         = "1"
      input_artifacts = ["SourceArtifacts"]	
		configuration = {
        BucketName = "${aws_s3_bucket.bucket.bucket}"
        Extract = "true"
      }
      
    }
  }
}


//Special thanks to Vimal Daga Sir
