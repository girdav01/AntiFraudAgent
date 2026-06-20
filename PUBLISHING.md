# Publishing Guide for AntiFraud Agent

This guide covers how to publish and distribute the AntiFraud CTI Agent.

## 📋 Pre-Publishing Checklist

- [ ] All tests passing
- [ ] Documentation complete
- [ ] Security review completed
- [ ] API keys removed from code
- [ ] Version number updated in `pyproject.toml`
- [ ] CHANGELOG.md updated
- [ ] README.md reviewed
- [ ] License file included (MIT)

## 🐳 Docker Hub

### 1. Build Multi-Platform Image

```bash
# Enable buildx
docker buildx create --use

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t yourusername/antifraud-agent:1.0.0 \
  -t yourusername/antifraud-agent:latest \
  --push \
  .
```

### 2. Create Docker Hub Repository

1. Go to https://hub.docker.com
2. Create repository: `antifraud-agent`
3. Set visibility (public/private)
4. Add README from repo

### 3. Push Images

```bash
docker login
docker push yourusername/antifraud-agent:1.0.0
docker push yourusername/antifraud-agent:latest
```

### 4. Update Docker Hub README

```markdown
# AntiFraud CTI Agent

Autonomous fraud detection and CTI enrichment with ML, webhooks, and STIX export.

## Quick Start

```bash
# Pull image
docker pull yourusername/antifraud-agent:latest

# Run with docker-compose
curl -O https://raw.githubusercontent.com/yourusername/AntiFraudAgent/main/docker-compose.yml
docker-compose up -d
```

## Documentation

Full docs: https://github.com/yourusername/AntiFraudAgent
```

## 📦 Python Package Index (PyPI)

### 1. Prepare Package

Ensure `pyproject.toml` is properly configured with:
- Version number
- Description
- Author information
- Dependencies
- Classifiers

### 2. Build Package

```bash
# Install build tools
pip install build twine

# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build
python -m build
```

### 3. Test on TestPyPI

```bash
# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Test installation
pip install --index-url https://test.pypi.org/simple/ antifraud-cti-agent
```

### 4. Publish to PyPI

```bash
# Upload to PyPI
twine upload dist/*
```

### 5. Verify Installation

```bash
pip install antifraud-cti-agent
```

## 🌐 GitHub Releases

### 1. Tag Release

```bash
git tag -a v1.0.0 -m "Release v1.0.0: Initial release with ML, webhooks, YARA, API"
git push origin v1.0.0
```

### 2. Create Release on GitHub

1. Navigate to your repository
2. Click "Releases" → "Draft a new release"
3. Select tag `v1.0.0`
4. Release title: `AntiFraud Agent v1.0.0`
5. Description:
   ```markdown
   ## 🎉 Features
   - Autonomous fraud detection agent
   - Multi-source CTI integration (URLHaus, VirusTotal, Trend Vision One)
   - ML-based fraud classification
   - Real-time webhook alerts
   - YARA rule generation
   - REST API with FastAPI
   - Jupyter notebook for analysis
   - STIX 2.1 export
   
   ## 📦 Installation
   
   ### Docker
   ```bash
   docker pull yourusername/antifraud-agent:1.0.0
   ```
   
   ### PyPI
   ```bash
   pip install antifraud-cti-agent
   ```
   
   ## 📖 Documentation
   See [README.md](https://github.com/yourusername/AntiFraudAgent/blob/main/README.md)
   ```

6. Attach files (optional):
   - Pre-built Docker image tarball
   - Python wheel file
   - Documentation PDF

### 3. Add GitHub Topics

Add relevant topics to your repository:
- `fraud-detection`
- `threat-intelligence`
- `cybersecurity`
- `machine-learning`
- `stix`
- `yara`
- `cti`
- `docker`
- `fastapi`
- `streamlit`

## ☁️ Cloud Marketplaces

### AWS Marketplace

1. **Prepare Container Image**
   ```bash
   # Tag for ECR
   docker tag antifraud-agent:latest your-account.dkr.ecr.us-east-1.amazonaws.com/antifraud-agent:1.0.0
   
   # Push to ECR
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin your-account.dkr.ecr.us-east-1.amazonaws.com
   docker push your-account.dkr.ecr.us-east-1.amazonaws.com/antifraud-agent:1.0.0
   ```

2. **Create Product Listing**
   - Go to AWS Marketplace Management Portal
   - Create new container product
   - Upload container image from ECR
   - Set pricing (free or paid)
   - Add product details and documentation

3. **Submit for Review**
   - AWS reviews typically take 2-4 weeks

### Azure Marketplace

1. **Create Container Offer**
   - Login to Partner Center
   - Create new Azure Container offer
   - Provide offer details

2. **Upload Container**
   ```bash
   # Login to ACR
   az acr login --name yourregistry
   
   # Tag and push
   docker tag antifraud-agent:latest yourregistry.azurecr.io/antifraud-agent:1.0.0
   docker push yourregistry.azurecr.io/antifraud-agent:1.0.0
   ```

3. **Complete Marketplace Listing**
   - Add pricing plans
   - Technical configuration
   - Marketing content
   - Submit for certification

### Google Cloud Marketplace

1. **Package as Kubernetes App**
   - Use our k8s manifests
   - Create deployer container
   - Test deployment

2. **Submit to Marketplace**
   - Create producer profile
   - Submit application
   - Complete listing details

## 🚀 Streamlit Community Cloud

### 1. Prepare Repository

Ensure these files exist:
- `ui/app.py` (main Streamlit app)
- `requirements.txt`
- `.streamlit/config.toml` (optional)

### 2. Deploy

1. Go to https://share.streamlit.io
2. Sign in with GitHub
3. Click "New app"
4. Select repository: `yourusername/AntiFraudAgent`
5. Main file path: `ui/app.py`
6. Click "Deploy"

### 3. Configure Secrets

Add secrets in Streamlit Cloud settings:
```toml
[secrets]
VIRUSTOTAL_API_KEY = "your-key"
TREND_API_KEY = "your-key"
```

## 📱 Mobile/Desktop Apps (Optional)

### Electron Desktop App

Package the Streamlit UI as desktop app:

```bash
npm install -g electron-packager

# Create electron wrapper
# Package for multiple platforms
electron-packager . AntiFraudAgent --platform=darwin,win32,linux --arch=x64
```

## 🔐 Security Considerations

Before publishing:

1. **Remove Secrets**
   - Ensure no API keys in code
   - Use environment variables
   - Add secrets to .gitignore

2. **Security Scan**
   ```bash
   # Scan Docker image
   docker scan antifraud-agent:latest
   
   # Scan Python dependencies
   pip install safety
   safety check
   ```

3. **Vulnerability Disclosure**
   - Add SECURITY.md
   - Set up security policy
   - Enable GitHub security advisories

4. **Code Signing**
   - Sign Docker images
   - Sign Python packages
   - Use GPG for git tags

## 📊 Analytics & Monitoring

### Docker Hub Stats

Monitor pulls and usage at:
https://hub.docker.com/r/yourusername/antifraud-agent/tags

### PyPI Stats

View download stats:
https://pypistats.org/packages/antifraud-cti-agent

### GitHub Insights

Monitor:
- Stars and forks
- Clone statistics
- Traffic analytics
- Community contributions

## 🎯 Marketing

### 1. Create Landing Page

Build a simple landing page with:
- Feature highlights
- Demo video/screenshots
- Installation instructions
- Documentation links

### 2. Write Blog Post

Publish on:
- Medium
- Dev.to
- Your personal blog

### 3. Social Media

Share on:
- Twitter/X
- LinkedIn
- Reddit (r/cybersecurity, r/netsec)
- Hacker News

### 4. Community Outreach

- Submit to Awesome lists (awesome-cybersecurity)
- Post on security forums
- Present at meetups/conferences
- Create YouTube tutorial

## 📝 Documentation Sites

### GitHub Pages

```bash
# Install MkDocs
pip install mkdocs mkdocs-material

# Create docs
mkdocs new .

# Build and deploy
mkdocs gh-deploy
```

### ReadTheDocs

1. Import project from GitHub
2. Configure build
3. Enable versioning

## 🔄 Continuous Deployment

### GitHub Actions

Create `.github/workflows/publish.yml`:

```yaml
name: Publish

on:
  release:
    types: [published]

jobs:
  publish-docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Login to Docker Hub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}
      
      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          push: true
          tags: yourusername/antifraud-agent:${{ github.ref_name }}
  
  publish-pypi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Build and publish
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
        run: |
          pip install build twine
          python -m build
          twine upload dist/*
```

## ✅ Post-Publishing

- [ ] Test installation from published sources
- [ ] Update documentation with installation instructions
- [ ] Respond to issues and pull requests
- [ ] Monitor analytics
- [ ] Plan next release

## 📞 Support

Provide support through:
- GitHub Issues
- GitHub Discussions
- Discord/Slack community
- Email support
- Documentation

---

**Need help with publishing?** Open an issue at https://github.com/yourusername/AntiFraudAgent/issues
