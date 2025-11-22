# CI/CD Setup Guide for Sandata

This guide will help you set up automated CI/CD for the Sandata project using GitHub Actions.

## Overview

The CI/CD pipeline includes:
- **Continuous Integration (CI)**: Automated testing, linting, and security scanning on every push/PR
- **Continuous Deployment (CD)**: Automated deployment to AWS EC2 when code is pushed to `main`

## Prerequisites

1. GitHub repository with the Sandata project
2. AWS EC2 instance running (16.52.149.96)
3. SSH access to the EC2 instance
4. GitHub account with repository access

## Step 1: Configure GitHub Secrets

Go to your GitHub repository and add the following secrets:

**Path**: `Settings > Secrets and variables > Actions > New repository secret`

### Required Secrets

| Secret Name | Description | How to Get |
|------------|-------------|------------|
| `AWS_EC2_HOST` | EC2 instance IP address | `16.52.149.96` |
| `AWS_EC2_USER` | SSH username | `ubuntu` |
| `AWS_SSH_PRIVATE_KEY` | SSH private key content | See below |
| `AWS_DEPLOY_PATH` | Application path on server | `/var/www/portfolio/sandata` |

### Getting SSH Private Key

On your local machine:

```bash
# Display the private key
cat ~/.ssh/swordfishproject.pem

# Copy the ENTIRE output including:
# -----BEGIN RSA PRIVATE KEY-----
# ... (all the key content) ...
# -----END RSA PRIVATE KEY-----
```

**Important**: Copy the entire key including the BEGIN and END lines.

### Adding Secrets in GitHub

1. Go to your repository on GitHub
2. Click `Settings` tab
3. Navigate to `Secrets and variables > Actions`
4. Click `New repository secret`
5. Enter the secret name (exactly as listed above)
6. Paste the value
7. Click `Add secret`
8. Repeat for all 4 secrets

## Step 2: Verify Workflow Files

The following workflow files should be in your repository:

```
.github/
└── workflows/
    ├── ci.yml          # CI workflow (testing, linting)
    ├── cd.yml          # CD workflow (deployment)
    └── README.md        # Workflow documentation
```

## Step 3: Test the CI Workflow

1. Make a small change to the code
2. Commit and push to a feature branch:
   ```bash
   git checkout -b test-ci
   git add .
   git commit -m "Test CI workflow"
   git push origin test-ci
   ```
3. Create a Pull Request to `main`
4. Go to `Actions` tab in GitHub
5. You should see the CI workflow running
6. Check that all tests pass

## Step 4: Test the CD Workflow

**Important**: CD only runs on pushes to `main` branch.

1. Merge your PR to `main` (or push directly to `main`)
2. Go to `Actions` tab
3. You should see the CD workflow running
4. Monitor the deployment steps
5. Verify deployment:
   ```bash
   curl https://sandata.janisrael.com/api/health
   ```

## Step 5: Verify Deployment on Server

SSH to your EC2 instance and verify:

```bash
ssh -i ~/.ssh/swordfishproject.pem ubuntu@16.52.149.96

# Check screen sessions
screen -list

# View application logs
screen -r sandata-app

# View Celery logs
screen -r sandata-celery

# Check if application is running
curl http://localhost:6000/api/health
```

## Workflow Details

### CI Workflow (`ci.yml`)

**Triggers:**
- Push to `main`, `develop`, or `features/**` branches
- Pull requests to `main` or `develop`

**Jobs:**
1. **Test**: Runs pytest with coverage
2. **Lint**: Checks code quality (flake8, black, isort)
3. **Security Scan**: Runs Bandit and TruffleHog

### CD Workflow (`cd.yml`)

**Triggers:**
- Push to `main` branch only
- Ignores changes to markdown files

**Steps:**
1. Run tests (must pass)
2. Configure SSH access
3. Deploy code to server
4. Restart application and Celery
5. Verify deployment

## Troubleshooting

### CI Workflow Fails

**Issue**: Tests fail
- Check test output in Actions tab
- Run tests locally: `pytest`
- Ensure all dependencies are in `requirements.txt`

**Issue**: Linting fails
- Run locally: `flake8 .` and `black --check .`
- Fix formatting: `black .`

**Issue**: Security scan finds issues
- Review Bandit output
- Fix security issues before merging

### CD Workflow Fails

**Issue**: SSH connection fails
- Verify `AWS_EC2_HOST` and `AWS_EC2_USER` are correct
- Check SSH key is correctly formatted (include BEGIN/END lines)
- Ensure EC2 security group allows SSH from GitHub Actions IPs

**Issue**: Deployment fails
- Check deployment logs in Actions tab
- SSH to server and check manually
- Verify `AWS_DEPLOY_PATH` is correct
- Ensure Git repository is initialized on server

**Issue**: Application doesn't start
- Check screen sessions: `screen -list`
- View logs: `screen -r sandata-app`
- Verify Redis is running: `sudo systemctl status redis`
- Check Python dependencies: `pip list`

### Manual Deployment

If automated deployment fails, deploy manually:

```bash
ssh -i ~/.ssh/swordfishproject.pem ubuntu@16.52.149.96
cd /var/www/portfolio/sandata
git pull origin main
source venv/bin/activate
pip install -r requirements.txt

# Restart application
screen -S sandata-app -X quit
screen -dmS sandata-app bash -c "source venv/bin/activate && python app.py"

# Restart Celery
screen -S sandata-celery -X quit
screen -dmS sandata-celery bash -c "source venv/bin/activate && celery -A celery_worker.celery worker --loglevel=info"
```

## Best Practices

1. **Always test locally** before pushing
2. **Review PRs** before merging to `main`
3. **Monitor deployments** after they complete
4. **Keep secrets secure** - never commit them
5. **Update dependencies** regularly
6. **Use feature branches** for development
7. **Write meaningful commit messages**

## Next Steps

After CI/CD is working:

1. Set up deployment notifications (Slack, Discord, Email)
2. Add staging environment
3. Implement blue-green deployment
4. Set up monitoring and alerts
5. Migrate to Kubernetes (update CD workflow accordingly)

## Support

If you encounter issues:
1. Check GitHub Actions logs
2. Review this guide
3. Check server logs
4. Verify all secrets are set correctly

---

**Status**: Ready for setup  
**Last Updated**: November 21, 2025

