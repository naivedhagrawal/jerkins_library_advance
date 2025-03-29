def call(Map config = [:]) {
    String GIT_URL = config.params?.GIT_URL ?: ''
    String GIT_BRANCH = config.params?.GIT_BRANCH ?: ''
    String GIT_CREDENTIALS_ID = config.params?.CREDENTIALS_ID ?: ''

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
        ]
    ) {
        node('securityscan-pod') {
            // Git Clone Stage
            stage('Git Clone') {
                container('git') {
                    if (GIT_CREDENTIALS_ID) {
                        withCredentials([usernamePassword(credentialsId: GIT_CREDENTIALS_ID, usernameVariable: 'GIT_USERNAME', passwordVariable: 'GIT_PASSWORD')]) {
                            sh """
                                echo "Git version:"
                                git --version
                                echo "Cloning repository from \${GIT_URL} - Branch: \${GIT_BRANCH}"
                                git config --global credential.helper cache
                                git config --global --add safe.directory $(pwd)
                                git clone --depth=1 --branch \${GIT_BRANCH} https://\${GIT_USERNAME}:\${GIT_PASSWORD}@\${GIT_URL.replaceFirst('https://', '')} .
                            """
                        }
                    } else {
                        sh """
                            echo "Cloning public repository from \${GIT_URL} - Branch: \${GIT_BRANCH}"
                            git clone --depth=1 --branch \${GIT_BRANCH} \${GIT_URL} .
                        """
                    }
                }
            }

            // Parallel Stages
            parallel(
                "Gitleaks Secret Scan": {
                    stage('Gitleaks Secret Scan') {
                        container('gitleak') {
                            sh """
                                echo "Gitleaks version:"
                                gitleaks version
                                echo "Running Gitleaks..."
                                gitleaks detect --source=. --report-path=reports/gitleaks-report.sarif --report-format sarif --exit-code=0
                                gitleaks detect --source=. --report-path=reports/gitleaks-report.json --report-format json --exit-code=0
                                gitleaks detect --source=. --report-path=reports/gitleaks-report.csv --report-format csv --exit-code=0
                            """
                        }
                    }
                },
                "OWASP Dependency Check": {
                    stage('OWASP Dependency Check') {
                        container('owasp') {
                            sh """
                                echo "OWASP Dependency Check version:"
                                /usr/share/dependency-check/bin/dependency-check.sh --version
                                echo "Running OWASP Dependency Check..."
                                mkdir -p reports
                                /usr/share/dependency-check/bin/dependency-check.sh --scan . \
                                    --format "SARIF" --out reports/ \
                                    --format "JSON" --out reports/ \
                                    --format "CSV" --out reports/ \
                                    --format "XML" --out reports/
                            """
                        }
                    }
                },
                "Semgrep Analysis": {
                    stage('Semgrep Analysis') {
                        container('semgrep') {
                            sh """
                                echo "Semgrep version:"
                                semgrep --version
                                semgrep --config=auto --sarif --output reports/semgrep-report.sarif .
                                semgrep --config=auto --json --output reports/semgrep-report.json .
                                semgrep --config=auto --verbose --output reports/semgrep-report.txt .
                            """
                        }
                    }
                },
                "Checkov IaC Scan": {
                    stage('Checkov IaC Scan') {
                        container('checkov') {
                            sh """
                                checkov --directory . \
                                    -o sarif --output-file reports/checkov-report.sarif \
                                    -o json --output-file reports/checkov-report.json \
                                    -o csv --output-file reports/checkov-report.csv || true
                            """
                        }
                    }
                }
            )

            // Archive all artifacts and record issues at once
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
                        owaspDependencyCheck(pattern: "reports/*.json", id: "OWASP", name: "Dependency Check Report")
                    ]
                )
            }
        }
    }
}
