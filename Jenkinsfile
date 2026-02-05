pipeline {
  agent any

  stages {
    stage('Checkout') { steps { checkout scm } }

    stage('Coverity via Jenkins Plugin') {
      steps {
        // Plugin provides steps that bind Coverity tools/config into env
        // (Exact step names depend on plugin + tool configuration in Jenkins Global Tool Config)
        withCoverityEnv(coverityToolName: 'coverity-2023', connectInstance: 'coverity-connect') {
          sh '''
            set -euo pipefail
            cov-build --dir idir npm ci && npm run build
            cov-analyze --dir idir --all
            cov-commit-defects --dir idir --stream juice-shop-main
          '''
        }
      }
    }
  }
}
