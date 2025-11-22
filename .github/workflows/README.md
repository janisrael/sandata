# GitHub Actions CI/CD Workflows

This directory contains automated CI/CD workflows for the Sandata project.

## Workflows

### 1. CI - Test & Quality Checks (`ci.yml`)

Runs on every push and pull request to `main`, `develop`, and feature branches.

**Jobs:**
- **Test**: Runs pytest with coverage reporting
- **Lint**: Checks code quality with flake8, black, and isort
- **Security Scan**: Runs Bandit security scanner and TruffleHog for secret detection

**Requirements:**
- Redis service (automatically provisioned)
- Python 3.13
- All dependencies from `requirements.txt`

### 2. CD - Deploy to AWS (`cd.yml`)

Runs on push to `main` branch (excluding markdown files).

**Steps:**
1. Run tests to ensure code quality
2. Configure SSH access to AWS EC2
3. Deploy code to server
4. Restart application and Celery worker
5. Verify deployment health

## Required GitHub Secrets

Configure these secrets in your GitHub repository settings (`Settings > Secrets and variables > Actions`):

### AWS Deployment Secrets

| Secret Name | Description | Example |
|------------|-------------|---------|
| `AWS_EC2_HOST` | EC2 instance IP address | `16.52.149.96` |
| `AWS_EC2_USER` | SSH username | `ubuntu` |
| `AWS_SSH_PRIVATE_KEY` | SSH private key content | Content of `~/.ssh/swordfishproject.pem` |
| `AWS_DEPLOY_PATH` | Application path on server | `/var/www/portfolio/sandata` |

### How to Add Secrets

1. Go to your GitHub repository
2. Navigate to `Settings > Secrets and variables > Actions`
3. Click `New repository secret`
4. Add each secret with the exact name listed above
5. Paste the value and save

### Getting SSH Private Key

```bash
# On your local machine
cat ~/.ssh/swordfishproject.pem
# Copy the entire output (including -----BEGIN and -----END lines)
```

## Workflow Triggers

### CI Workflow
- Triggers on push to: `main`, `develop`, `features/**`
- Triggers on pull requests to: `main`, `develop`
- Runs all test and quality checks

### CD Workflow
- Triggers only on push to: `main`
- Ignores changes to: `*.md`, `.gitignore`, `README.md`, `docs/**`
- Deploys automatically after successful tests

## Manual Workflow Dispatch

You can also trigger workflows manually:

1. Go to `Actions` tab in GitHub
2. Select the workflow
3. Click `Run workflow`
4. Choose branch and click `Run workflow`

## Monitoring

### View Workflow Runs
- Go to `Actions` tab in GitHub
- See status of all workflow runs
- Click on a run to see detailed logs

### Deployment Verification
After deployment, verify the application:
```bash
curl https://sandata.janisrael.com/api/health
```

Expected response:
```json
{"status": "ok", "version": "2.0"}
```

## Troubleshooting

### CI Fails
- Check test output in Actions tab
- Ensure all dependencies are in `requirements.txt`
- Verify Redis service is accessible

### CD Fails
- Verify all secrets are correctly set
- Check SSH key permissions (should be 600)
- Ensure EC2 instance is accessible
- Verify deployment path exists on server
- Check screen sessions are not conflicting

### Deployment Issues
- SSH to server and check logs:
  ```bash
  ssh -i ~/.ssh/swordfishproject.pem ubuntu@16.52.149.96
  screen -r sandata-app  # View application logs
  screen -r sandata-celery  # View Celery logs
  ```

## Best Practices

1. **Always test locally** before pushing to `main`
2. **Review PRs** before merging to `main`
3. **Monitor deployments** after they complete
4. **Keep secrets secure** - never commit them to the repository
5. **Update dependencies** regularly in `requirements.txt`

## Future Enhancements

- [ ] Add deployment notifications (Slack, Discord, Email)
- [ ] Implement blue-green deployment
- [ ] Add rollback capability
- [ ] Set up staging environment
- [ ] Add performance testing
- [ ] Integrate with Kubernetes deployment

