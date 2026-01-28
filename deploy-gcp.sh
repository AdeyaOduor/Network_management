#!/bin/bash
# deploy-gcp.sh
set -e

echo "Deploying GCP Vulnerability Scanner..."

PROJECT_ID=$(gcloud config get-value project)
REGION="us-central1"

# Install dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements-gcp.txt -t ./package

# Create deployment package
echo "Creating deployment package..."
cd package
zip -r9 ../vulnerability_scanner_gcp.zip .
cd ..
zip -g vulnerability_scanner_gcp.zip scanner_gcp.py
zip -g vulnerability_scanner_gcp.zip config_gcp.yaml

# Upload to Cloud Storage
echo "Uploading function code..."
gsutil mb -p $PROJECT_ID -l $REGION gs://function-code-$PROJECT_ID || true
gsutil cp vulnerability_scanner_gcp.zip gs://function-code-$PROJECT_ID/

# Deploy with Terraform
echo "Deploying infrastructure..."
cd terraform-gcp
terraform init
terraform apply -auto-approve -var="project_id=$PROJECT_ID" -var="region=$REGION"

# Create config file from template
echo "Creating configuration..."
envsubst < ../config_gcp.template.yaml > ../config_gcp.yaml

echo "Deployment complete!"
echo "Next steps:"
echo "1. Review the IAM permissions granted to the service account"
echo "2. Test the Cloud Function manually from the Console"
echo "3. Verify reports are being generated in Cloud Storage"
echo "4. Check BigQuery for exported findings"
