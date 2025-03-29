def call(Map params = [:]) {
    def uniqueLabel = "security-scan-${UUID.randomUUID().toString()}"  // Generate unique label

    podTemplate(
        label: uniqueLabel,  // Use dynamic label
        containers: [
            containerTemplate(name: 'gitleak', image: 'zricethezav/gitleaks:latest', command: 'cat', ttyEnabled: true, alwaysPullImage: true),
            containerTemplate(name: 'owasp', image: 'owasp/dependency-check-action:latest', command: 'cat', ttyEnabled: true, alwaysPullImage: true),
            containerTemplate(name: 'semgrep', image: 'returntocorp/semgrep:latest', command: 'cat', ttyEnabled: true, alwaysPullImage: true),
            containerTemplate(name: 'checkov', image: 'bridgecrew/checkov:latest', command: 'cat', ttyEnabled: true, alwaysPullImage: true),
            containerTemplate(name: 'sonarscanner', image: 'sonarsource/sonar-scanner-cli:latest', command: 'cat', ttyEnabled: true, alwaysPullImage: true),
            containerTemplate(
                name: 'sonarqube',
                image: 'sonarqube:community',
                command: '',                // ✅ Use default entrypoint
                ttyEnabled: true,
                alwaysPullImage: true,
                ports: [portMapping(name: 'sonar', containerPort: 9000, hostPort: 9000)]
            )
        ],
        envVars: [
            envVar(key: 'GIT_SSL_NO_VERIFY', value: 'false')
        ],
        showRawYaml: false
    ) {
        node(uniqueLabel) {  // Use the same dynamic label for the node
            stage('Checkout Code') {
                checkout scm
            }

            // 🚀 Parallel Security Scans
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
                                recordIssues(
                                    enabledForFailure: true,
                                    tools: [sarif(pattern: "gitleaks-report.sarif", id: "Secrets", name: "Secret Scanning Report", icon: "symbol-key")],
                                    qualityGates: [
                                        [threshold: 5, type: 'TOTAL', unstable: true],
                                        [threshold: 2, type: 'NEW', unstable: true]
                                    ]
                                )
                            }
                        }
                    },
                    "OWASP Dependency Check": {
                        stage('OWASP Dependency Check') {
                            container('owasp') {
                                sh '''
                                    mkdir -p reports
                                    echo "Running OWASP Dependency Check..."
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
                                recordIssues(
                                    enabledForFailure: true,
                                    tools: [owaspDependencyCheck(pattern: "owasp-report.json", id: "Vulnerability", name: "Dependency Check Report")],
                                    qualityGates: [
                                        [threshold: 20, type: 'TOTAL', unstable: true],
                                        [threshold: 8, type: 'NEW', unstable: true]
                                    ]
                                )
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
                                recordIssues(
                                    enabledForFailure: true,
                                    tools: [sarif(pattern: "semgrep-report.sarif", id: "StaticAnalysis", name: "Static Analysis Report", icon: "symbol-error")],
                                    qualityGates: [
                                        [threshold: 15, type: 'TOTAL', unstable: true],
                                        [threshold: 5, type: 'NEW', unstable: true]
                                    ]
                                )
                            }
                        }
                    },
                    "Checkov IaC Scan": {
                        stage('Checkov IaC Scan') {
                            container('checkov') {
                                sh '''
                                    checkov --directory . -o sarif -o csv || true
                                '''
                                recordIssues(
                                    enabledForFailure: true,
                                    tools: [sarif(pattern: "results.sarif", id: "IaC", name: "IaC Vulnerability Report", icon: "symbol-cloud")],
                                    qualityGates: [
                                        [threshold: 10, type: 'TOTAL', unstable: true],
                                        [threshold: 4, type: 'NEW', unstable: true]
                                    ]
                                )
                            }
                        }
                    },
                    "SonarQube Analysis": {
                        stage('SonarQube Analysis') {
                            container('sonarscanner') {
                                sh '''
                                    echo "Waiting for SonarQube server to be ready..."
                                    sleep 60  # ✅ Wait for SonarQube to be fully initialized
                                    sonar-scanner -Dsonar.host.url=http://localhost:9000 -Dsonar.qualitygate.wait=false -Dsonar.projectKey=local-analysis -Dsonar.sources=.
                                '''
                                recordIssues(
                                    enabledForFailure: true,
                                    tools: [genericIssueParser(pattern: '**/sonar-report.json', name: 'SonarQube Analysis', id: 'SonarQube')],
                                    qualityGates: [
                                        [threshold: 10, type: 'TOTAL', unstable: true],
                                        [threshold: 5, type: 'NEW', unstable: true]
                                    ]
                                )
                            }
                        }
                    }
                )
            }
            
            stage('Archive Results') {
                archiveArtifacts artifacts: "gitleaks-report.sarif, gitleaks-report.csv, semgrep-report.sarif, results.sarif, *iac.csv, owasp-report.sarif, owasp-report.json, owasp-report.csv, owasp-report.xml"
            }
        }
    }
}
