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
            containerTemplate(name: 'git', image: 'alpine/git:latest', command: 'cat', ttyEnabled: true, imagePullPolicy: 'Always', alwaysPullImage: true),
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
                                    gitleaks detect --source=. --report-path=gitleaks-report.sarif --report-format sarif --exit-code=0          
                                    gitleaks detect --source=. --report-path=gitleaks-report.csv --report-format csv --exit-code=0
                                '''
                            }
                        }
                    },
                    "OWASP Dependency Check": {
                        stage('OWASP Dependency Check') {
                            container('owasp') {
                                sh '''
                                    mkdir -p reports
                                    echo "Running OWASP Dependency Check..."
                                    echo "OWASP Dependency Check version:"
                                    /usr/share/dependency-check/bin/dependency-check.sh --version
                                    echo "Scanning for vulnerabilities..."
                                    /usr/share/dependency-check/bin/dependency-check.sh --scan . \
                                        --format "SARIF" \
                                        --format "JSON" \
                                        --format "CSV" \
                                        --format "XML" \
                                        --exclude "**/*.zip" \
                                        --out "reports/"
                                    
                                    mv reports/dependency-check-report.sarif owasp-report.sarif
                                    mv reports/dependency-check-report.json owasp-report.json
                                    mv reports/dependency-check-report.csv owasp-report.csv
                                    mv reports/dependency-check-report.xml owasp-report.xml
                                '''
                            }
                        }
                    },
                    "Semgrep Analysis": {
                        stage('Semgrep Analysis') {
                            container('semgrep') {
                                sh '''
                                    semgrep --version
                                    semgrep --config=auto --sarif --output semgrep-report.sarif .
                                    
                                '''
                                /*semgrep --config=auto --verbose --output semgrep-report.txt .*/
                            }
                        }
                    },
                    "Checkov IaC Scan": {
                        stage('Checkov IaC Scan') {
                            container('checkov') {
                                sh '''
                                    checkov --quiet --compact --directory . \
                                        -o sarif -o csv || true
                                '''
                            }
                        }
                    }
                )
            }

            // ✅ Archive reports only after all parallel stages finish
            stage('Archival and Report Generation') {
                sh "ls -lh"
                archiveArtifacts artifacts: "gitleaks-report.sarif, gitleaks-report.csv, semgrep-report.sarif, semgrep-report.txt, results.sarif, results.csv, owasp-report.sarif, owasp-report.json, owasp-report.csv, owasp-report.xml"

                recordIssues(
                    enabledForFailure: true,
                    tools: [
                        sarif(pattern: "gitleaks-report.sarif", id: "Secrets", name: "Secret Scanning Report", icon: "symbol-key"),
                        sarif(pattern: "semgrep-report.sarif", id: "StaticAnalysis", name: "Static Analysis Report", icon: "symbol-error"),
                        sarif(pattern: "results.sarif", id: "IaC", name: "IaC Vulnerability Report", icon: "symbol-cloud"),
                        owaspDependencyCheck(pattern: "owasp-report.json", id: "Vulnerability", name: "Dependency Check Report")
                    ]
                )
            }
        }
    }
}
