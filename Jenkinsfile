pipeline {
  agent any
  environment {
    POLARIS_SERVER_URL = credentials('polaris-server-url') // or use a string credential
    POLARIS_ACCESS_TOKEN = credentials('polaris-access-token')
  }

  stages {
    stage('Checkout') { steps { checkout scm } }

    stage('Download Bridge CLI') {
      steps {
        sh '''
          set -euo pipefail
          mkdir -p .ci-tools
          # Example: download Bridge bundle from your internal mirror or official repo per docs
          # (POC: place your real download method here)
          echo "Download bridge-cli to .ci-tools/bridge"
        '''
      }
    }

    stage('Polaris SAST via Bridge CLI') {
      steps {
        sh '''
          set -euo pipefail
          chmod +x .ci-tools/bridge || true
          .ci-tools/bridge --stage polaris --input bridge.yml
        '''
      }
    }
  }
}
