def call(Map params = [:]) {
    String GIT_URL = ''
    String GIT_BRANCH = ''
    if (params instanceof Map) {
        def nestedParams = params['params'] ?: params
        GIT_URL = nestedParams['GIT_URL'] ?: ''
        GIT_BRANCH = nestedParams['GIT_BRANCH'] ?: ''
    } else {
        error "params is not a Map."
    }
    if (!GIT_URL || !GIT_BRANCH) {
        error "GIT_URL or GIT_BRANCH is not set!"
    }

    podTemplate(
        label: 'securityscan-pod',
        containers: [
            containerTemplate(name: 'git', image: 'alpine/git:latest', command: 'cat', ttyEnabled: true),
            containerTemplate(name: 'gitleak', image: 'zricethezav/gitleaks:latest', command: 'cat', ttyEnabled: true),
            containerTemplate(name: 'owasp', image: 'owasp/dependency-check-action:latest', command: 'cat', ttyEnabled: true),
            containerTemplate(name: 'semgrep', image: 'returntocorp/semgrep:latest', command: 'cat', ttyEnabled: true),
            containerTemplate(name: 'checkov', image: 'bridgecrew/checkov:latest', command: 'cat', ttyEnabled: true)
        ],
        envVars: [
            envVar(key: 'GIT_SSL_NO_VERIFY', value: 'false')  // Enforce SSL verification for better security
        ],
        showRawYaml: false
    ) {
        node('securityscan-pod') {
            
            stage('Git Clone') {
                container('git') {
                    withEnv(["GIT_URL=${GIT_URL}", "GIT_BRANCH=${GIT_BRANCH}"]) {
                        sh '''
                            echo "Cloning repository from $GIT_URL - Branch: $GIT_BRANCH"
                            git --version
                            git config --global --add safe.directory $PWD
                            git clone --depth=1 --branch $GIT_BRANCH $GIT_URL .
                            mkdir -p reports
                        '''
                    }
                }
            }

            // Execute parallel scans
            stage('Run Security Scans') {
                parallel(
                    "Gitleaks Secret Scan": {
                        stage('Gitleaks Secret Scan') {
                            container('gitleak') {
                                sh '''
                                    gitleaks version
                                    gitleaks detect --source=. --report-path=reports/gitleaks-report.sarif --report-format sarif --exit-code=0          
                                    gitleaks detect --source=. --report-path=reports/gitleaks-report.csv --report-format csv --exit-code=0
                                '''
                            }
                        }
                    },
                    "OWASP Dependency Check": {
                        stage('OWASP Dependency Check') {
                            container('owasp') {
                                sh '''
                                    /usr/share/dependency-check/bin/dependency-check.sh --scan . \
                                        --format "SARIF" --out reports/owasp-report.sarif \
                                        --format "JSON" --out reports/owasp-report.json \
                                        --format "CSV" --out reports/owasp-report.csv \
                                        --format "XML" --out reports/owasp-report.xml
                                '''
                            }
                        }
                    },
                    "Semgrep Analysis": {
                        stage('Semgrep Analysis') {
                            container('semgrep') {
                                sh '''
                                    semgrep --version
                                    semgrep --config=auto --sarif --output reports/semgrep-report.sarif .
                                    semgrep --config=auto --verbose --output reports/semgrep-report.txt .
                                '''
                            }
                        }
                    },
                    "Checkov IaC Scan": {
                        stage('Checkov IaC Scan') {
                            container('checkov') {
                                sh '''
                                    checkov --quiet --directory . \
                                        -o sarif --output-file reports/checkov-report.sarif \
                                        -o csv --output-file reports/checkov-report.csv || true
                                '''
                            }
                        }
                    }
                )
            }

            // ✅ Archive reports only after all parallel stages finish
            stage('Archive and Report') {
                sh "ls -lh reports"
                archiveArtifacts artifacts: "reports/*"

                recordIssues(
                    enabledForFailure: true,
                    aggregatingResults: true,
                    tools: [
                        sarif(pattern: "reports/gitleaks-report.sarif", id: "Gitleaks", name: "Secret Scanning Report"),
                        sarif(pattern: "reports/semgrep-report.sarif", id: "Semgrep", name: "Static Analysis Report"),
                        sarif(pattern: "reports/checkov-report.sarif", id: "Checkov", name: "IaC Vulnerability Report"),
                        owaspDependencyCheck(pattern: "reports/owasp-report.json", id: "OWASP", name: "Dependency Check Report")
                    ]
                )
            }
        }
    }
}
