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
            containerTemplate(name: 'git', image: 'alpine/git:latest', command: 'cat', ttyEnabled: true,),
            containerTemplate(name: 'gitleak', image: 'zricethezav/gitleaks:latest', command: 'cat', ttyEnabled: true,),
            containerTemplate(name: 'owasp', image: 'owasp/dependency-check-action:latest', command: 'cat', ttyEnabled: true,),
            containerTemplate(name: 'semgrep', image: 'returntocorp/semgrep:latest', command: 'cat', ttyEnabled: true,),
            containerTemplate(name: 'checkov', image: 'bridgecrew/checkov:latest', command: 'cat', ttyEnabled: true,),
            containerTemplate(name: 'syft', image: 'anchore/syft:latest', command: '/usr/local/bin/syft', args: 'packages . -o json', ttyEnabled: true),
            containerTemplate(name: 'grype', image: 'anchore/grype:latest', command: '/usr/local/bin/grype', args: 'dir:.', ttyEnabled: true)
        ],
        envVars: [
            envVar(key: 'GIT_SSL_NO_VERIFY', value: 'false')  // Ensure SSL verification is ON
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
                    "SBOM Generation and Vulnerability Scan": {
                        stage('SBOM and Grype Scan') {
                            container('syft') {
                                sh '''
                                    syft . -o json > sbom.json
                                '''
                            }
                            container('grype') {
                                sh '''
                                    grype sbom:./sbom.json -o json > grype-report.json || true
                                '''
                                recordIssues(
                                    enabledForFailure: true,
                                    tools: [sarif(pattern: "grype-report.json", id: "SBOM", name: "SBOM Vulnerability Report", icon: "symbol-package")],
                                    
                                    qualityGates: [
                                        [threshold: 15, type: 'TOTAL', unstable: true],
                                        [threshold: 5, type: 'NEW', unstable: true]
                                    ]
                                )
                            }
                        }
                    }
                )
            }
            
            stage('Archive Results') {
                archiveArtifacts artifacts: "gitleaks-report.sarif, gitleaks-report.csv, semgrep-report.sarif, results.sarif, *iac.csv, owasp-report.sarif, owasp-report.json, owasp-report.csv, owasp-report.xml, sbom.json, grype-report.json"
            }
        }
    }
}