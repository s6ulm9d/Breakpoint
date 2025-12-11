# 🔌 CI/CD Integration Guide

Integrate **BREAKPOINT** into your automated pipelines to ensure resilience with every commit.

---

## 🏗️ GitHub Actions

Create `.github/workflows/security-audit.yml`:

```yaml
name: Nightly Security Audit

on:
  schedule:
    - cron: '0 2 * * *' # Run at 2 AM
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install Breakpoint
        run: |
          pip install git+https://github.com/soulmad/breakpoint.git

      - name: Run Fire Drill
        run: |
          breakpoint \
            --base-url ${{ secrets.STAGING_URL }} \
            --force-live-fire \
            --sarif-report results.sarif \
            --json-report audit.json

      - name: Upload Artifacts
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: |
            results.sarif
            audit.json

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 🦊 GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
security_audit:
  stage: test
  image: python:3.10
  script:
    - pip install git+https://github.com/soulmad/breakpoint.git
    - breakpoint --base-url $STAGING_URL --force-live-fire --json-report gl-dast-report.json
  artifacts:
    paths:
      - gl-dast-report.json
    when: always
  allow_failure: true
```

---

## 🐳 Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Audit') {
            steps {
                sh 'pip install git+https://github.com/soulmad/breakpoint.git'
                sh 'breakpoint --base-url http://staging.local --force-live-fire --html-report report.html'
            }
            post {
                always {
                    publishHTML(target: [
                        reportName: 'Breakpoint Audit',
                        reportDir: '.',
                        reportFiles: 'report.html'
                    ])
                }
            }
        }
    }
}
```
